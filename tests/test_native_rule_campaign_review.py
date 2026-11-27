"""Offline campaign evidence tests. Native server and label provenance are not simulated as qualified."""
import copy
import datetime as dt
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import native_rule_campaign_review as review
import native_rule_replay as replay
import native_rule_shadow_runner as shadow
from test_native_rule_replay import A, B, CONFIG, START

PREVIEW = {"changes": {k: ([{"id": A, "operation": "update"}] if k == "rules" else []) for k in review.TYPES}}
HASH = "a"*64
CFG = shadow.config(json.dumps({"replay": {**{k: v for k, v in CONFIG.items() if k not in ("from", "until")},
    "expected_test_sha256": HASH, "expected_custom_sha256": "b"*64}, "first_window": START, "window_seconds": 3600}))
FIRST = int(replay.utc(START).timestamp())
ATTEST = {"author": "rule-author", "reviewer": "independent-reviewer", "review_plan_sha256": "c"*64, "reason": "Review evidence"}


def receipt(start, end, prefix, populated=True):
    rows = []
    if populated:
        for i in range(20):
            # Ten positives retained, ten false positives removed.
            rows.append({"index": ".ds-wazuh-events-v5-security-000001", "id": prefix+str(i),
                         "source_sha256": replay.sha([prefix, i]), "baseline": [A],
                         "candidate": [A] if i < 10 else [], "gained": [], "lost": [] if i < 10 else [A]})
    return {"format": "wazuh-native-paired-replay-v1", "scope": {**review.scope(CFG["replay"]),
                "from": shadow.iso(dt.datetime.fromtimestamp(start, dt.timezone.utc)),
                "until": shadow.iso(dt.datetime.fromtimestamp(end, dt.timezone.utc))},
            "observed_at": dt.datetime.fromtimestamp(end+120, dt.timezone.utc).isoformat(),
            "test_sha256": HASH, "custom_sha256": "b"*64, "preview_sha256": replay.sha(PREVIEW),
            "event_count": len(rows), "baseline_matches": len(rows), "candidate_matches": len(rows)//2,
            "gained_matches": 0, "lost_matches": len(rows)//2, "rows": rows,
            "coverage": "exact_search_telemetry_unverified", "promotion_authorized": False}


def labels(receipts):
    return [{**{k: row[k] for k in ("index", "id", "source_sha256")}, "rule_uuid": A,
             "truth": "positive" if i < 10 else "negative"} for r in receipts for i, row in enumerate(r["rows"])]


class CampaignReviewTests(unittest.TestCase):
    def setUp(self):
        self.historical = [receipt(FIRST-7200, FIRST-3600, "historical-")]
        self.live = [receipt(FIRST+i*3600, FIRST+(i+1)*3600, f"live-{i}-", populated=i==0) for i in range(24)]
        self.labels = {"historical": labels(self.historical), "prospective": labels(self.live)}

    def run_review(self):
        return review.review(PREVIEW, self.historical, (CFG, FIRST-1, self.live), self.labels, ATTEST)

    def test_complete_pack_is_review_only(self):
        pack = self.run_review()
        self.assertEqual(pack["status"], "ready_for_independent_release_review")
        self.assertFalse(pack["promotion_authorized"])
        self.assertEqual(pack["prospective_seconds"], 86400)
        self.assertEqual(pack["prospective_events"], 20)
        self.assertEqual(pack["historical_metrics"][A]["removed_false_positive"], 10)
        self.assertEqual(pack["prospective_metrics"][A]["lost_positive"], 0)

    def test_regression_unknown_and_short_duration_block(self):
        self.labels["historical"][10]["truth"] = "positive"
        self.labels["prospective"][0]["truth"] = "unknown"
        self.live.pop()
        pack = self.run_review()
        self.assertEqual(pack["status"], "blocked")
        self.assertIn(A+":historical:regression", pack["blockers"])
        self.assertIn(A+":prospective:insufficient_labels", pack["blockers"])
        self.assertIn("prospective_duration_under_24h", pack["blockers"])

    def test_bad_label_and_content_drift_fail_closed(self):
        self.labels["historical"][0]["source_sha256"] = "0"*64
        with self.assertRaises(ValueError):
            self.run_review()
        self.labels["historical"] = labels(self.historical)
        self.live[-1]["test_sha256"] = "0"*64
        with self.assertRaises(ValueError):
            self.run_review()

    def test_unrelated_delta_and_reused_identity_rejected(self):
        first = self.live[0]["rows"][0]
        first["candidate"].append(B)
        first["gained"] = [B]
        self.live[0]["candidate_matches"] += 1
        self.live[0]["gained_matches"] = 1
        with self.assertRaises(ValueError):
            self.run_review()
        self.live[0] = receipt(FIRST, FIRST+3600, "historical-")
        with self.assertRaises(ValueError):
            self.run_review()

    def test_non_rule_changes_and_self_review_rejected(self):
        other = copy.deepcopy(PREVIEW)
        other["changes"]["decoders"] = [{"id": B, "operation": "update"}]
        with self.assertRaises(ValueError):
            review.changed_rules(other)
        with self.assertRaises(ValueError):
            review.review(PREVIEW, self.historical, (CFG, FIRST-1, self.live), self.labels, {**ATTEST, "reviewer": ATTEST["author"]})

    def test_sqlite_read_only_and_missing_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"state.sqlite"
            db = shadow.open_state(path, CFG, FIRST-1)
            for i, row in enumerate(self.live):
                db.execute("INSERT INTO windows VALUES (?,?)", (FIRST+i*3600, replay.canonical(row)))
            db.commit()
            cfg, registered, rows = review.read_campaign(path, replay.sha(PREVIEW))
            self.assertEqual(cfg, CFG)
            self.assertEqual(registered, FIRST-1)
            self.assertEqual(rows, self.live)
            db.execute("DELETE FROM windows WHERE start=?", (FIRST+3600,))
            db.commit()
            with self.assertRaises(ValueError):
                review.read_campaign(path, replay.sha(PREVIEW))
            db.close()


if __name__ == "__main__":
    unittest.main()
