import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("replay", Path(__file__).resolve().parents[1] / "tools/incident_tuning_replay.py")
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


def response(evaluated=1, matched=0, status="success"):
    return {"status": 200, "message": {"status": status, "rules_evaluated": evaluated,
                                      "rules_matched": matched, "matches": [{}] * matched}}


def fixture():
    return {"split": "holdout",
            "controls": [{"id": "positive", "label": "malicious", "input": {"expected": True}},
                         {"id": "negative", "label": "benign", "input": {"expected": False}}],
            "rows": [{"id": "one", "label": "malicious", "input": {"expected": True}},
                     {"id": "two", "label": "benign", "input": {"expected": False}}]}


class ReplayTests(unittest.TestCase):
    def test_response_contract(self):
        self.assertTrue(replay.detection_result(response(matched=1)))
        self.assertFalse(replay.detection_result(response()))
        for body in (response(evaluated=0), response(evaluated=2), response(status="error"),
                     response(matched=2), response(evaluated=True), {"status": 200, "message": {}},
                     {"status": 200, "message": {**response()["message"], "matches": [{}]}}):
            with self.assertRaises(ValueError):
                replay.detection_result(body)

    def test_loopback_only(self):
        self.assertEqual(replay.endpoint("https://127.0.0.1:9200"), "https://127.0.0.1:9200" + replay.PATH)
        for bad in ("http://127.0.0.1:9200", "https://example.org:9200", "https://localhost:9200",
                    "https://127.0.0.1", "https://u:p@127.0.0.1:9200", "https://127.0.0.1:9200/path"):
            with self.assertRaises(ValueError):
                replay.endpoint(bad)

    def test_fixture_and_controls(self):
        call = lambda event: event["expected"]
        result = replay.run_replay(fixture(), call, call, "a" * 64, "b" * 64)
        self.assertEqual(result["receipt"]["paired_count"], 2)
        self.assertEqual(result["receipt"]["fixture_sha256"], replay.paired_digest(result["fixture"]["rows"]))
        self.assertNotIn("expected", str(result))
        with self.assertRaises(ValueError):
            replay.run_replay(fixture(), call, lambda event: False, "a" * 64, "b" * 64)
        duplicate = fixture()
        duplicate["rows"][0]["id"] = "positive"
        with self.assertRaises(ValueError):
            replay.validate_fixture(duplicate)
        with self.assertRaises(ValueError):
            replay.strict_json('{"a":1,"a":2}')

    def test_final_control_failure(self):
        count = 0
        def changing(event):
            nonlocal count
            count += 1
            return event["expected"] if count <= 4 else False
        with self.assertRaises(ValueError):
            replay.run_replay(fixture(), lambda event: event["expected"], changing, "a" * 64, "b" * 64)


if __name__ == "__main__":
    unittest.main()
