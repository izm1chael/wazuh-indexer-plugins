#!/usr/bin/env python3
"""Offline evidence pack for native rule-only promotion review. Never authorizes or calls promotion."""
import argparse
import datetime as dt
import os
import re
import sqlite3
import sys
from pathlib import Path

import native_rule_replay as replay
import native_rule_shadow_runner as shadow
from incident_analytics_runner import unique_json

MAX_WINDOWS = 288
MAX_ROWS = 30000
TYPES = {"policy", "integrations", "kvdbs", "decoders", "filters", "rules"}
HASH = re.compile(r"[a-f0-9]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    require(isinstance(value, str) and HASH.fullmatch(value), "Expected SHA256")
    return value


def changed_rules(preview):
    require(isinstance(preview, dict) and set(preview) == {"changes"}, "Exact native preview required")
    changes = preview["changes"]
    require(isinstance(changes, dict) and set(changes) == TYPES, "Complete native changes required")
    require(all(isinstance(v, list) for v in changes.values()), "Invalid native change lists")
    require(all(not changes[k] for k in TYPES-{"rules"}), "Only rule-only updates supported")
    rules = []
    for item in changes["rules"]:
        require(isinstance(item, dict) and set(item) == {"id", "operation"} and item["operation"] == "update",
                "Only existing rule updates supported")
        rules.append(replay.identity(item["id"]))
    require(0 < len(rules) <= 20 and len(set(rules)) == len(rules), "Invalid changed rule population")
    return sorted(rules)


def scope(cfg):
    return {k: cfg[k] for k in ("integration", "cluster", "space", "dataset")}


def validate_receipt(receipt, cfg, preview_hash):
    require(isinstance(receipt, dict) and set(receipt) == {"format", "scope", "observed_at", "test_sha256", "custom_sha256",
            "preview_sha256", "event_count", "baseline_matches", "candidate_matches", "gained_matches", "lost_matches",
            "rows", "coverage", "promotion_authorized"}, "Invalid replay receipt")
    require(receipt["format"] == "wazuh-native-paired-replay-v1" and receipt["coverage"] == "exact_search_telemetry_unverified"
            and receipt["promotion_authorized"] is False, "Unsupported receipt")
    require(digest(receipt["test_sha256"]) == cfg["expected_test_sha256"] and
            digest(receipt["custom_sha256"]) == cfg["expected_custom_sha256"] and
            digest(receipt["preview_sha256"]) == preview_hash, "Content or preview drift")
    s = receipt["scope"]
    require(isinstance(s, dict) and set(s) == set(scope(cfg)) | {"from", "until"} and
            all(s[k] == v for k, v in scope(cfg).items()), "Replay scope mismatch")
    start, end = replay.utc(s["from"]), replay.utc(s["until"])
    observed = dt.datetime.fromisoformat(receipt["observed_at"].replace("Z", "+00:00"))
    require(observed.utcoffset() == dt.timedelta(0) and dt.timedelta(0) < end-start <= dt.timedelta(days=1)
            and observed >= end+dt.timedelta(seconds=120), "Invalid receipt timing")
    rows = receipt["rows"]
    require(isinstance(rows, list) and len(rows) <= replay.MAX_EVENTS, "Invalid rows")
    counts = dict(baseline_matches=0, candidate_matches=0, gained_matches=0, lost_matches=0)
    seen = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"index", "id", "source_sha256", "baseline", "candidate", "gained", "lost"},
                "Invalid event pair")
        require(isinstance(row["index"], str) and replay.EVENT_INDEX.fullmatch(row["index"]) and replay.literal(row["id"], 512),
                "Invalid event identity")
        key = (row["index"], row["id"])
        require(key not in seen, "Duplicate event")
        seen.add(key)
        digest(row["source_sha256"])
        for name in ("baseline", "candidate", "gained", "lost"):
            ids = row[name]
            require(isinstance(ids, list) and len(ids) <= replay.MAX_RULES and ids == sorted(set(ids)), "Invalid match list")
            for ident in ids:
                replay.identity(ident)
            counts[name+"_matches"] += len(ids)
        require(set(row["gained"]) == set(row["candidate"])-set(row["baseline"]) and
                set(row["lost"]) == set(row["baseline"])-set(row["candidate"]), "Pair delta mismatch")
    require(type(receipt["event_count"]) is int and receipt["event_count"] == len(rows) and
            all(type(receipt[k]) is int and receipt[k] == v for k, v in counts.items()), "Count conservation failed")
    return start, end


def read_campaign(path, preview_hash):
    # Read-only database snapshot. Do not create schema or mutate the runner cursor.
    with sqlite3.connect(path.resolve().as_uri()+"?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        stored = db.execute("SELECT definition,registered FROM scope WHERE slot=1").fetchone()
        require(stored is not None, "No prospective registration")
        cfg = shadow.config(stored[0])
        first = int(replay.utc(cfg["first_window"]).timestamp())
        require(type(stored[1]) is int and stored[1] < first, "Nonprospective registration")
        windows = db.execute("SELECT start,length(receipt) FROM windows ORDER BY start LIMIT ?", (MAX_WINDOWS+1,)).fetchall()
        require(0 < len(windows) <= MAX_WINDOWS and all(0 < size <= 8_000_000 for _, size in windows) and
                sum(size for _, size in windows) <= 64_000_000, "Campaign empty or exceeds review budget")
        receipts = []
        for n, (start, _) in enumerate(windows):
            require(start == first+n*cfg["window_seconds"], "Missing window")
            raw = db.execute("SELECT receipt FROM windows WHERE start=?", (start,)).fetchone()[0]
            receipt = unique_json(raw)
            a, z = validate_receipt(receipt, cfg["replay"], preview_hash)
            require(a.timestamp() == start and z.timestamp() == start+cfg["window_seconds"], "Window identity mismatch")
            receipts.append(receipt)
        db.rollback()
    return cfg, stored[1], receipts


def population(receipts, rules, cfg, preview_hash, seen):
    rows = {}
    previous = None
    for receipt in receipts:
        start, end = validate_receipt(receipt, cfg, preview_hash)
        require(previous is None or start >= previous, "Overlapping or unordered replay intervals")
        previous = end
        for row in receipt["rows"]:
            key = (row["index"], row["id"])
            require(key not in seen, "Event reused across evidence partitions")
            seen.add(key)
            require(len(seen) <= MAX_ROWS, "Evidence budget exceeded")
            require(set(row["gained"]+row["lost"]) <= set(rules), "Unexpected detection delta outside changed rules")
            rows[key] = row
    return rows


def metrics(rows, labels, rules):
    require(isinstance(labels, list) and len(labels) == len(rows)*len(rules), "Label population incomplete")
    require(len(labels) <= MAX_ROWS*20, "Label budget exceeded")
    result = {rule: dict(positive=0, negative=0, unknown=0, lost_positive=0, gained_positive=0,
                        new_false_positive=0, removed_false_positive=0,
                        baseline_tp=0, baseline_fp=0, baseline_tn=0, baseline_fn=0,
                        candidate_tp=0, candidate_fp=0, candidate_tn=0, candidate_fn=0) for rule in rules}
    seen = set()
    for label in labels:
        require(isinstance(label, dict) and set(label) == {"index", "id", "source_sha256", "rule_uuid", "truth"}, "Invalid label")
        key = (label["index"], label["id"])
        rule, truth = label["rule_uuid"], label["truth"]
        require(rule in result and truth in {"positive", "negative", "unknown"} and key in rows and
                rows[key]["source_sha256"] == label["source_sha256"] and (key, rule) not in seen, "Label identity mismatch")
        seen.add((key, rule))
        row, m = rows[key], result[rule]
        m[truth] += 1
        if truth == "unknown":
            continue
        a, b = rule in row["baseline"], rule in row["candidate"]
        if truth == "positive":
            m["baseline_tp" if a else "baseline_fn"] += 1
            m["candidate_tp" if b else "candidate_fn"] += 1
            m["lost_positive"] += int(a and not b)
            m["gained_positive"] += int(b and not a)
        else:
            m["baseline_fp" if a else "baseline_tn"] += 1
            m["candidate_fp" if b else "candidate_tn"] += 1
            m["new_false_positive"] += int(not a and b)
            m["removed_false_positive"] += int(a and not b)
    return result


def review(preview, historical, campaign, labels, approval):
    rules = changed_rules(preview)
    preview_hash = replay.sha(preview)
    cfg, registered, prospective = campaign
    require(isinstance(historical, list) and 0 < len(historical) <= MAX_WINDOWS, "Historical holdout required")
    require(isinstance(approval, dict) and set(approval) == {"author", "reviewer", "review_plan_sha256", "reason"} and
            all(replay.literal(approval[k], 1024) for k in ("author", "reviewer", "reason")) and
            approval["author"] != approval["reviewer"], "Independent review attestation required")
    digest(approval["review_plan_sha256"])
    require(isinstance(labels, dict) and set(labels) == {"historical", "prospective"}, "Separate label partitions required")
    # Historical holdout must precede registration, not simply precede the first replay window.
    require(all(replay.utc(r["scope"]["until"]).timestamp() <= registered for r in historical), "Historical holdout overlaps campaign registration")
    seen = set()
    old = population(historical, rules, cfg["replay"], preview_hash, seen)
    live = population(prospective, rules, cfg["replay"], preview_hash, seen)
    h, p = metrics(old, labels["historical"], rules), metrics(live, labels["prospective"], rules)
    blockers = []
    if len(prospective)*cfg["window_seconds"] < 86400:
        blockers.append("prospective_duration_under_24h")
    for rule in rules:
        for name, m in (("historical", h[rule]), ("prospective", p[rule])):
            if m["positive"] < 10 or m["negative"] < 10 or m["unknown"]:
                blockers.append(rule+":"+name+":insufficient_labels")
            if m["lost_positive"] or m["new_false_positive"]:
                blockers.append(rule+":"+name+":regression")
        if not h[rule]["gained_positive"] and not h[rule]["removed_false_positive"]:
            blockers.append(rule+":historical:no_improvement")
    return {"format": "wazuh-native-rule-review-pack-v1", "status": "blocked" if blockers else "ready_for_independent_release_review",
            "blockers": blockers, "scope": scope(cfg["replay"]), "changed_rules": rules,
            "test_sha256": cfg["replay"]["expected_test_sha256"], "custom_sha256": cfg["replay"]["expected_custom_sha256"],
            "preview_sha256": preview_hash, "review_plan_sha256": approval["review_plan_sha256"],
            "historical_receipt_sha256": [replay.sha(r) for r in historical],
            "prospective_receipt_sha256": [replay.sha(r) for r in prospective],
            "labels_sha256": replay.sha(labels), "review_attestation": approval,
            "registered_epoch": registered, "prospective_windows": len(prospective),
            "prospective_seconds": len(prospective)*cfg["window_seconds"],
            "historical_events": len(old), "prospective_events": len(live), "historical_metrics": h, "prospective_metrics": p,
            "coverage": "exact_search_telemetry_unverified", "promotion_authorized": False}


def read(path, limit):
    require(path.stat().st_size <= limit, "Input exceeds review budget")
    return unique_json(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("preview", "historical", "state", "labels", "attestation", "output"):
        parser.add_argument("--"+name, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        preview = read(args.preview, 1_000_000)
        campaign = read_campaign(args.state, replay.sha(preview))
        pack = review(preview, read(args.historical, 64_000_000), campaign,
                      read(args.labels, 64_000_000), read(args.attestation, 16_000))
        with args.output.open("x", encoding="utf-8") as out:
            out.write(replay.canonical(pack)+"\n")
            out.flush()
            os.fsync(out.fileno())
        print(pack["status"]+"; no promotion authorized")
        return 0 if not pack["blockers"] else 2
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, OverflowError, sqlite3.Error):
        print("Evidence review blocked; no promotion authorized", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
