"""Offline publication protocol and replay tests; no live indexer or credentials."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import incident_behaviour_publish_runner as publisher
import incident_rule_behaviour_runner as runner

DAY = runner.DAY
FIRST = runner.epoch("2026-11-25T00:00:00Z")
NOW = FIRST + DAY + 120
CONFIG = {"endpoint": "https://indexer.example.invalid:9200", "username": "publisher", "ca_file": "/ca.pem",
          "deployment_id": "00000000-0000-4000-8000-000000000001", "policy_id": "00000000-0000-4000-8000-000000000002",
          "policy_version": 1, "field": "user.name", "value": "alice", "rule_uuid": "00000000-0000-4000-8000-000000000001",
          "first_day": runner.utc(FIRST)}


def receipt(query, count=5):
    day = runner.epoch(query["day"])
    return {"id": publisher.observation_id(CONFIG, day), "query": query, "actor": "publisher",
            "model": "rule_volume_v2", "observed_at": runner.utc(day+DAY+120),
            "coverage": "search_complete_telemetry_unverified", "finding_count": 56+count,
            "assessment": runner.assess([2]*28, count), "recorded": True}


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "state.sqlite"
        self.cfg = {**runner.config(json.dumps(CONFIG)), "mode": "shared_observation_v1"}
        self.db = runner.open_state(self.path, self.cfg)
        self.addCleanup(self.db.close)

    def tick(self, send=receipt, now=NOW):
        return publisher.run_due(self.db, self.cfg, send, now, lambda _: None)

    def test_identity_matches_java(self):
        self.assertEqual(publisher.fingerprint(self.cfg), "7a265b3f73c0a9adf58122bfdd9d2bf0ea1cc1bfa8d0948c3c6ac749d88a06bc")
        self.assertEqual(publisher.observation_id(self.cfg, FIRST), "197591c7-8a01-840e-9b4c-02f888e34dd7")
        self.assertNotEqual(publisher.observation_id(self.cfg, FIRST+DAY), publisher.observation_id(self.cfg, FIRST))

    def test_zero_and_replay(self):
        self.assertEqual(self.tick(lambda q: receipt(q, count=0)), 0)
        stored = json.loads(self.db.execute("SELECT receipt FROM observations").fetchone()[0])
        self.assertEqual(stored["assessment"]["current_count"], 0)
        self.assertNotIn("query", stored)
        self.assertEqual(self.tick(lambda _: self.fail("Already committed")), 0)
        self.assertEqual(runner.next_day(self.db, self.cfg), FIRST+DAY)

    def test_remote_commit_then_response_loss_and_old_receipt(self):
        recorded = []
        def lost(query):
            recorded.append(receipt(query))
            raise RuntimeError("response lost")
        self.assertEqual(self.tick(lost), 1)
        self.assertEqual(runner.next_day(self.db, self.cfg), FIRST)
        self.assertEqual(self.tick(lambda _: recorded[0], NOW+9*DAY), 0)
        self.assertEqual(runner.next_day(self.db, self.cfg), FIRST+DAY)

    def test_invalid_receipt_does_not_advance(self):
        for changes in ({"id": "other"}, {"actor": "other"}, {"recorded": False}, {"finding_count": 99},
                        {"coverage": "complete"}, {"observed_at": runner.utc(NOW-1)},
                        {"observed_at": runner.utc(NOW+301)}, {"review": None}):
            self.assertEqual(self.tick(lambda q: {**receipt(q), **changes}), 1)
            self.assertEqual(runner.next_day(self.db, self.cfg), FIRST)
        self.assertEqual(self.tick(), 0)

    def test_local_only_state_cannot_be_reused(self):
        with self.assertRaises(ValueError):
            runner.open_state(self.path, runner.config(json.dumps(CONFIG)))

    def test_future_not_sent(self):
        self.assertEqual(self.tick(lambda _: self.fail("Future day"), NOW-1), 0)
        self.assertEqual(runner.next_day(self.db, self.cfg), FIRST)


if __name__ == "__main__":
    unittest.main()
