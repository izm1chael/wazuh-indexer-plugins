"""Offline tests for the rule behaviour scheduler; no network or live data."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import incident_rule_behaviour_runner as runner

DAY = runner.DAY
FIRST = runner.epoch("2026-11-25T00:00:00Z")
NOW = FIRST + DAY + 120
CONFIG = {"endpoint": "https://indexer.example.invalid:9200", "username": "behaviour-runner", "ca_file": "/ca.pem",
          "deployment_id": "00000000-0000-4000-8000-000000000001", "policy_id": "00000000-0000-4000-8000-000000000002",
          "policy_version": 1, "field": "user.name", "value": "alice", "rule_uuid": "00000000-0000-4000-8000-000000000003",
          "first_day": runner.utc(FIRST)}


def report(query, now=NOW, count=5):
    day = runner.epoch(query["day"])
    return {"scope": "caller_visible_rule_finding_scan", "model": "rule_volume_v2", "query": query,
            "baseline_from": runner.utc(day-28*DAY), "until": runner.utc(day+DAY), "finding_count": 56+count,
            "assessment": runner.assess([2]*28, count), "coverage": "search_complete_telemetry_unverified",
            "actor": CONFIG["username"], "observed_at": runner.utc(now),
            "current_sample": [{"index": ".ds-wazuh-findings-v5-security-000001", "document_id": f"id-{n}",
                                "timestamp": query["day"]} for n in range(min(20, count))]}


class RuleBehaviourRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite"
        self.cfg = runner.config(json.dumps(CONFIG))
        self.db = runner.open_state(self.path, self.cfg)
        self.addCleanup(self.db.close)
        self.messages = []

    def tick(self, send=report, now=NOW):
        return runner.run_due(self.db, self.cfg, send, now, self.messages.append)

    def test_config_rejects_unbounded_or_changed_scope(self):
        for changes in ({"endpoint": "http://example.invalid"}, {"endpoint": "https://user:secret@example.invalid"},
                        {"field": "arbitrary.field"}, {"field": "source.ip", "value": "001.2.3.4"},
                        {"first_day": "2026-11-25T00:01:00Z"}, {"policy_version": True}, {"rule_uuid": "unknown"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.config(json.dumps({**CONFIG, **changes}))
        with self.assertRaises(ValueError):
            runner.open_state(self.path, {**self.cfg, "value": "bob"})

    def test_exact_statistics(self):
        self.assertEqual(runner.assess([0]*28, 0)["classification"], "no_observed_activity")
        self.assertEqual(runner.assess([0]*28, 1)["classification"], "newly_observed")
        self.assertEqual(runner.assess([1]+[0]*27, 100)["classification"], "sparse_baseline")
        self.assertEqual(runner.assess([2]*28, 5)["classification"], "elevated_rule_volume")
        self.assertEqual(runner.assess([0]*14+[10]*14, 20)["threshold"], 20)
        self.assertEqual(runner.assess([1]*14+[2]*14, 5)["mad_times_four"], 2)
        self.assertEqual(runner.assess([40]+[1]*27, 42)["threshold"], 43)
        with self.assertRaises(ValueError):
            runner.assess([72]*28, 0)

    def test_persist_and_replay_without_finding_sample(self):
        self.assertEqual(self.tick(), 0)
        row = self.db.execute("SELECT day, receipt FROM observations").fetchone()
        self.assertEqual(row[0], FIRST)
        receipt = json.loads(row[1])
        self.assertEqual(receipt["assessment"]["classification"], "elevated_rule_volume")
        self.assertNotIn("current_sample", receipt)
        self.assertNotIn("id-0", row[1])
        self.assertEqual(len(receipt["response_sha256"]), 64)
        with runner.open_state(self.path, self.cfg) as reopened:
            self.assertEqual(runner.next_day(reopened, self.cfg), FIRST+DAY)
        self.assertEqual(self.tick(lambda _: self.fail("already recorded day must not rerun")), 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 1)

    def test_failed_request_retains_day_and_retry_succeeds(self):
        def fail(_):
            raise RuntimeError("unavailable")
        self.assertEqual(self.tick(fail), 1)
        self.assertEqual(runner.next_day(self.db, self.cfg), FIRST)
        self.assertEqual(self.tick(), 0)
        self.assertEqual(runner.next_day(self.db, self.cfg), FIRST+DAY)

    def test_receipt_identity_and_counts_fail_closed(self):
        for changes in ({"actor": "other"}, {"finding_count": 62}, {"coverage": "complete"},
                        {"observed_at": runner.utc(NOW-1)}, {"observed_at": runner.utc(NOW+301)}, {"current_sample": []},
                        {"assessment": {**runner.assess([2]*28, 5), "threshold": 4}}):
            with self.subTest(changes=changes):
                self.assertEqual(self.tick(lambda q: {**report(q), **changes}), 1)
                self.assertEqual(runner.next_day(self.db, self.cfg), FIRST)
        def duplicate(q):
            value = report(q)
            value["current_sample"][1] = value["current_sample"][0]
            return value
        self.assertEqual(self.tick(duplicate), 1)
        self.assertEqual(runner.next_day(self.db, self.cfg), FIRST)

    def test_zero_result_is_recorded_and_consecutive_day_advances(self):
        self.assertEqual(self.tick(lambda q: report(q, count=0)), 0)
        self.assertEqual(self.tick(lambda q: report(q, now=NOW+DAY), NOW+DAY), 0)
        self.assertEqual(runner.next_day(self.db, self.cfg), FIRST+2*DAY)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 2)

    def test_future_and_old_gap_do_not_query(self):
        never = lambda _: self.fail("query must not run")
        self.assertEqual(self.tick(never, NOW-1), 0)
        self.assertEqual(self.tick(never, FIRST+8*DAY), 1)
        self.assertEqual(runner.next_day(self.db, self.cfg), FIRST)

    def test_noncontiguous_ledger_is_rejected(self):
        self.assertEqual(self.tick(), 0)
        self.db.execute("INSERT INTO observations VALUES (?,?)", (FIRST+2*DAY, "{}"))
        self.db.commit()
        with self.assertRaises(ValueError):
            runner.next_day(self.db, self.cfg)


if __name__ == "__main__":
    unittest.main()
