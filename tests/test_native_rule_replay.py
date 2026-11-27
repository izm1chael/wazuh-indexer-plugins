"""Offline fixtures for paired native replay and prospective cursor; no real indexer."""
import copy
import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import native_rule_replay as replay
import native_rule_shadow_runner as shadow

INTEGRATION = "00000000-0000-4000-8000-000000000001"
A = "00000000-0000-4000-8000-000000000002"
B = "00000000-0000-4000-8000-000000000003"
START = "2026-11-25T00:00:00Z"
END = "2026-11-25T00:05:00Z"
NOW = replay.utc(END) + dt.timedelta(seconds=120)
CONFIG = {"endpoint": "https://indexer.example.invalid:9200", "username": "replay-reader", "ca_file": "/ca.pem",
          "integration": INTEGRATION, "cluster": "lab", "space": "standard", "dataset": "sshd", "from": START, "until": END,
          "expected_test_sha256": None, "expected_custom_sha256": None}


def hit(index, ident, source):
    return {"_index": index, "_id": ident, "_seq_no": 1, "_primary_term": 1, "_source": source}


def response(rows):
    return {"timed_out": False, "_shards": {"total": 1, "failed": 0}, "hits": {"total": {"relation": "eq", "value": len(rows)}, "hits": rows}}


def result(evaluated, ids):
    return {"status": 200, "message": {"status": "success", "rules_evaluated": evaluated,
                                      "rules_matched": len(ids), "matches": [{"rule": {"id": i}} for i in ids]}}


class NativeFixture:
    def __init__(self):
        self.calls = []
        self.event_rows = [hit(".ds-wazuh-events-v5-access-management-000001", "event-1", {
            "@timestamp": START, "wazuh": {"cluster": {"name": "lab"}, "space": {"name": "standard"}},
            "event": {"dataset": "sshd", "original": "sensitive fixture"}})]
        self.changed = False
        self.bad_count = False
        self.preview = {"changes": {"rules": [{"operation": "update", "id": A}]}}
        self.change_on_match = False

    def __call__(self, method, path, body=None):
        self.calls.append((method, path))
        if path.startswith("/wazuh-threatintel-integrations/"):
            space = body["query"]["bool"]["filter"][0]["term"]["space.name"]
            rules = [A, B] if space == "test" else [A]
            return response([hit("wazuh-threatintel-integrations", space+"-integration", {
                "space": {"name": space}, "document": {"id": INTEGRATION, "rules": rules}})])
        if path.startswith("/wazuh-threatintel-rules/"):
            space = body["query"]["bool"]["filter"][0]["term"]["space.name"]
            rules = [A, B] if space == "test" else [A]
            return response([hit("wazuh-threatintel-rules", space+rule, {
                "space": {"name": space}, "document": {"id": rule, "enabled": True, "version": 2 if self.changed and space == "test" else 1}}) for rule in rules])
        if path.startswith("/wazuh-events-v5*/"):
            return response(self.event_rows)
        if path == replay.ROOT+"/promote?space=test":
            return copy.deepcopy(self.preview)
        if path == replay.ROOT+"/logtest/detection":
            assert body["input"] == self.event_rows[0]["_source"]
            if self.change_on_match:
                self.changed = True
            return result(1, [A]) if body["space"] == "custom" else result(0 if self.bad_count else 2, [B])
        raise AssertionError("Unexpected operation")

    def pinned(self):
        cfg = dict(CONFIG)
        cfg["expected_test_sha256"] = replay.content_snapshot(self, cfg, "test")[0]
        cfg["expected_custom_sha256"] = replay.content_snapshot(self, cfg, "custom")[0]
        return cfg


class ReplayTests(unittest.TestCase):
    def test_native_paired_deltas_and_no_source_in_receipt(self):
        fixture = NativeFixture()
        receipt = replay.replay(fixture, fixture.pinned(), NOW, pace=lambda: None)
        self.assertEqual(receipt["event_count"], 1)
        self.assertEqual(receipt["gained_matches"], 1)
        self.assertEqual(receipt["lost_matches"], 1)
        self.assertEqual(receipt["rows"][0]["candidate"], [B])
        self.assertEqual(receipt["rows"][0]["baseline"], [A])
        self.assertFalse(receipt["promotion_authorized"])
        self.assertNotIn("sensitive fixture", replay.canonical(receipt))
        self.assertNotIn(("POST", replay.ROOT+"/promote"), fixture.calls)

    def test_content_change_and_incomplete_evaluation_fail_closed(self):
        fixture = NativeFixture()
        cfg = fixture.pinned()
        fixture.bad_count = True
        with self.assertRaises(ValueError):
            replay.replay(fixture, cfg, NOW, pace=lambda: None)
        fixture.bad_count = False
        fixture.change_on_match = True
        with self.assertRaises(ValueError):
            replay.replay(fixture, cfg, NOW, pace=lambda: None)
        with self.assertRaises(ValueError):
            replay.replay(fixture, cfg, NOW, pace=lambda: None)

    def test_empty_is_not_qualification_and_future_rejected(self):
        fixture = NativeFixture()
        cfg = fixture.pinned()
        fixture.event_rows = []
        receipt = replay.replay(fixture, cfg, NOW, pace=lambda: None)
        self.assertEqual(receipt["event_count"], 0)
        self.assertFalse(receipt["promotion_authorized"])
        with self.assertRaises(ValueError):
            replay.replay(fixture, cfg, NOW-dt.timedelta(seconds=1), pace=lambda: None)

    def test_source_identity_and_partial_search(self):
        fixture = NativeFixture()
        cfg = fixture.pinned()
        fixture.event_rows[0]["_source"]["event"]["dataset"] = "different"
        with self.assertRaises(ValueError):
            replay.replay(fixture, cfg, NOW, pace=lambda: None)
        for changes in ({"timed_out": True}, {"_shards": {"total": 0, "failed": 0}}, {"_shards": {"total": 1, "failed": 1}}):
            with self.assertRaises(ValueError):
                replay.search(lambda *_: {**response([]), **changes}, "wazuh-events-v5*", [], 100)
        with self.assertRaises(ValueError):
            replay.search(lambda *_: response([fixture.event_rows[0]]*2), "wazuh-events-v5*", [], 100)
        with self.assertRaises(ValueError):
            replay.matched(result(1, [B]), {A})

    def test_config_and_scope(self):
        self.assertEqual(replay.config(json.dumps(CONFIG)), CONFIG)
        for patch in ({"endpoint": "http://example.invalid"}, {"from": START.replace("Z", ".000Z")}, {"integration": "not-uuid"}):
            with self.assertRaises(ValueError):
                replay.config(json.dumps({**CONFIG, **patch}))


class ShadowTests(unittest.TestCase):
    def setUp(self):
        self.fixture = NativeFixture()
        core = {k: v for k, v in self.fixture.pinned().items() if k not in ("from", "until")}
        self.cfg = shadow.config(json.dumps({"replay": core, "first_window": START, "window_seconds": 300}))
        self.start = int(replay.utc(START).timestamp())
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state.sqlite"
        self.db = shadow.open_state(self.path, self.cfg, self.start-1)
        self.addCleanup(self.db.close)

    def run_replay(self, send, query, now):
        return replay.replay(send, query, now, pace=lambda: None)

    def test_prospective_registration_commit_and_retry(self):
        self.assertEqual(shadow.tick(self.db, self.cfg, self.start+419, self.fixture, self.run_replay), "NO_DUE_WINDOW")
        self.assertTrue(shadow.tick(self.db, self.cfg, self.start+420, self.fixture, self.run_replay).startswith("RECORDED_WINDOW"))
        self.assertEqual(shadow.next_window(self.db, self.cfg), self.start+300)
        self.assertEqual(shadow.tick(self.db, self.cfg, self.start+420, self.fixture, self.run_replay), "NO_DUE_WINDOW")
        with self.assertRaises(ValueError):
            shadow.open_state(Path(self.tmp.name)/"late.sqlite", self.cfg, self.start)

    def test_failed_window_and_changed_scope_block(self):
        self.fixture.bad_count = True
        with self.assertRaises(ValueError):
            shadow.tick(self.db, self.cfg, self.start+420, self.fixture, self.run_replay)
        self.assertEqual(shadow.next_window(self.db, self.cfg), self.start)
        with self.assertRaises(ValueError):
            shadow.tick(self.db, self.cfg, self.start+90000, self.fixture, self.run_replay)
        with self.assertRaises(ValueError):
            shadow.open_state(self.path, {**self.cfg, "window_seconds": 600}, self.start+1)


if __name__ == "__main__":
    unittest.main()
