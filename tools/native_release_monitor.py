#!/usr/bin/env python3
"""Read-only post-release content reconciliation and equal-window finding-volume review."""
import argparse
import datetime as dt
import os
import re
import sys
from pathlib import Path

import native_rule_replay as replay
from incident_analytics_runner import unique_json

FINDING_INDEX = re.compile(r"(?:\.ds-)?wazuh-findings-v5-[a-z0-9][a-z0-9-]*-[0-9]{6}")
RELEASE_READ = "/_plugins/_setup/detection-releases/read"
MAX_FINDINGS = 2000
MAX_EVENTS = 2000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hash_value(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value), "Invalid digest")
    return value


def instant(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", value),
            "Invalid UTC timestamp")
    return replay.utc(value)


def config(raw):
    cfg = unique_json(raw)
    require(isinstance(cfg, dict) and set(cfg) == {"endpoint", "username", "ca_file", "plan_sha256",
            "baseline_from", "baseline_until", "post_from", "post_until"}, "Invalid monitor configuration")
    hash_value(cfg["plan_sha256"])
    # Reuse fixed origin, credential and interval validation; identity is obtained only from ledger.
    transport_cfg = replay.config(replay.canonical({"endpoint": cfg["endpoint"], "username": cfg["username"], "ca_file": cfg["ca_file"],
        "integration": "00000000-0000-4000-8000-000000000001", "cluster": "placeholder", "space": "placeholder", "dataset": "placeholder",
        "from": cfg["baseline_from"], "until": cfg["baseline_until"], "expected_test_sha256": None, "expected_custom_sha256": None}))
    cfg["endpoint"] = transport_cfg["endpoint"]
    for field in ("baseline_from", "baseline_until", "post_from", "post_until"):
        require(isinstance(cfg[field], str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", cfg[field]),
                "Canonical second-resolution UTC window required")
    a, b, c, d = (instant(cfg[k]) for k in ("baseline_from", "baseline_until", "post_from", "post_until"))
    require(dt.timedelta(0) < b-a == d-c <= dt.timedelta(days=1) and b <= c, "Equal disjoint windows required")
    return cfg


def read_release(send, plan):
    row = send("POST", RELEASE_READ, {"id": plan})
    require(isinstance(row, dict) and set(row) == {"format", "id", "evidence", "author", "submitted_at", "state", "revision",
            "review", "reservation", "outcome"}, "Invalid release record")
    require(row["format"] == "wazuh-detection-release-v1" and row["id"] == plan and row["state"] == "native_reported"
            and type(row["revision"]) is int and row["revision"] == 4, "Native release outcome not recorded")
    review, reservation, outcome = row["review"], row["reservation"], row["outcome"]
    require(isinstance(review, dict) and review["decision"] == "approved" and
            isinstance(reservation, dict) and reservation["actor"] == review["deployer"] and
            isinstance(outcome, dict) and type(outcome["native_status"]) is int and outcome["native_status"] in (200, 202),
            "Native acceptance not recorded")
    require(instant(row["submitted_at"]) <= instant(review["at"]) <= instant(reservation["at"]) < instant(review["expires"])
            and instant(reservation["at"]) <= instant(outcome["at"]), "Release chronology mismatch")
    e = row["evidence"]
    require(isinstance(e, dict) and e["pack_sha256"] == review["pack_sha256"], "Evidence mismatch")
    for key in ("pack_sha256", "test_sha256", "custom_sha256", "preview_sha256", "labels_sha256"):
        hash_value(e[key])
    replay.identity(e["integration"])
    for key in ("cluster", "space", "dataset"):
        require(replay.literal(e[key]), "Invalid monitored scope")
    rules = e["changed_rules"]
    require(isinstance(rules, list) and 0 < len(rules) <= 20 and rules == sorted(set(rules)), "Invalid reviewed rules")
    for rule in rules:
        replay.identity(rule)
    return row


def content_check(send, e):
    test = replay.content_details(send, e, "test")
    custom = replay.content_details(send, e, "custom")
    require(test["sha256"] == e["test_sha256"], "Reviewed Test snapshot changed; cannot verify expected content")
    require(set(e["changed_rules"]) <= set(test["rules"]) and set(e["changed_rules"]) <= set(custom["rules"]),
            "Reviewed rules missing from native integration")
    # Exact document body comparison; metadata/seq_no/space wrapper intentionally excluded.
    # Any representation change blocks rather than guessing semantic equivalence.
    checks = []
    for rule in e["changed_rules"]:
        expected, actual = replay.sha(test["rules"][rule]), replay.sha(custom["rules"][rule])
        checks.append({"rule_uuid": rule, "expected_document_sha256": expected, "actual_document_sha256": actual,
                       "equal": expected == actual})
    return {"test_snapshot_sha256": test["sha256"], "custom_snapshot_sha256": custom["sha256"],
            "integration_document_equal": replay.sha(test["integration"]) == replay.sha(custom["integration"]),
            "all_integration_rule_documents_equal": test["rules"] == custom["rules"],
            "reviewed_rules": checks}


def population(send, e, start, end, finding):
    terms = {"wazuh.cluster.name": e["cluster"], "wazuh.space.name": e["space"], "event.dataset": e["dataset"]}
    filters = [{"term": {key: value}} for key, value in terms.items()]
    filters.append({"range": {"@timestamp": {"gte": start, "lt": end}}})
    if finding:
        filters.append({"bool": {"should": [{"terms": {"wazuh.rule.uuid": e["changed_rules"]}},
                    {"terms": {"rule.uuid": e["changed_rules"]}}], "minimum_should_match": 1}})
    hits = replay.search(send, "wazuh-findings-v5*" if finding else "wazuh-events-v5*", filters,
                         MAX_FINDINGS if finding else MAX_EVENTS)
    counts = {rule: 0 for rule in e["changed_rules"]}
    identities = []
    for hit in hits:
        src = hit["_source"]
        require((FINDING_INDEX if finding else replay.EVENT_INDEX).fullmatch(hit["_index"]) and replay.literal(hit["_id"], 512),
                "Invalid concrete source identity")
        require(all(replay.scalar(src, k) == v for k, v in terms.items()) and
                instant(start) <= instant(replay.scalar(src, "@timestamp")) < instant(end), "Source scope mismatch")
        identities.append([hit["_index"], hit["_id"], hit["_seq_no"], hit["_primary_term"]])
        if finding:
            # Missing alias is allowed; conflicting aliases are not.
            rule_values = []
            for key in ("wazuh.rule.uuid", "rule.uuid"):
                try:
                    value = replay.scalar(src, key)
                except ValueError:
                    # scalar() rejects missing intermediate parents. Distinguish absent from ambiguous.
                    def optional(node, parts):
                        if not isinstance(node, dict):
                            raise ValueError("Ambiguous finding rule")
                        rest = ".".join(parts)
                        if len(parts)>1 and rest in node:
                            require(parts[0] not in node, "Mixed rule representation")
                            return node[rest]
                        if parts[0] not in node:
                            return None
                        return node[parts[0]] if len(parts)==1 else optional(node[parts[0]], parts[1:])
                    value = optional(src, key.split("."))
                if value is not None:
                    rule_values.append(replay.identity(value))
            require(len(set(rule_values)) == 1 and rule_values[0] in counts, "Conflicting or missing rule identity")
            counts[rule_values[0]] += 1
    result = {"count": len(hits), "population_sha256": replay.sha(identities)}
    if finding:
        result["by_rule"] = counts
    return result


def monitor(send, cfg, now):
    plan = cfg["plan_sha256"]
    row = read_release(send, plan)
    e = row["evidence"]
    a, b, c, d = (instant(cfg[k]) for k in ("baseline_from", "baseline_until", "post_from", "post_until"))
    # Exclude the deployment interval; don't claim these are pre/post if clocks or windows disagree.
    require(b <= instant(row["reservation"]["at"]) and c >= instant(row["outcome"]["at"]) and
            d <= now-dt.timedelta(seconds=120) and a >= now-dt.timedelta(days=30), "Window outside release chronology or retention review budget")
    content = content_check(send, e)
    baseline = {"events": population(send, e, cfg["baseline_from"], cfg["baseline_until"], False),
                "findings": population(send, e, cfg["baseline_from"], cfg["baseline_until"], True)}
    post = {"events": population(send, e, cfg["post_from"], cfg["post_until"], False),
            "findings": population(send, e, cfg["post_from"], cfg["post_until"], True)}
    require(read_release(send, plan) == row and content_check(send, e) == content, "Release or content changed during observation")
    result = []
    for rule in e["changed_rules"]:
        before, after = baseline["findings"]["by_rule"][rule], post["findings"]["by_rule"][rule]
        result.append({"rule_uuid": rule, "baseline_findings": before, "post_findings": after, "delta": after-before,
                       "classification": "no_observed_post_findings" if not after else "higher_observed_volume" if after > before else
                                         "lower_observed_volume" if after < before else "same_observed_volume"})
    return {"format": "wazuh-native-post-release-review-v1", "plan_sha256": plan, "pack_sha256": e["pack_sha256"],
            "scope": {k: e[k] for k in ("integration", "cluster", "space", "dataset")},
            "observed_at": now.isoformat(), "native_status": row["outcome"]["native_status"],
            "reserved_at": row["reservation"]["at"], "native_reported_at": row["outcome"]["at"],
            "windows": {k: cfg[k] for k in ("baseline_from", "baseline_until", "post_from", "post_until")},
            "content": content, "baseline": baseline, "post": post, "rules": result,
            "coverage": "exact_search_telemetry_unverified", "deployment_verified": False,
            "automatic_rollback_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        require(args.config.stat().st_size <= 16384, "Oversize config")
        cfg = config(args.config.read_text(encoding="utf-8"))
        send = replay.transport(cfg, os.environ.pop("WAZUH_RELEASE_MONITOR_PASSWORD", ""))
        result = monitor(send, cfg, dt.datetime.now(dt.timezone.utc))
        with args.output.open("x", encoding="utf-8") as out:
            out.write(replay.canonical(result)+"\n")
            out.flush()
            os.fsync(out.fileno())
        print("RECORDED read-only post-release evidence; no deployment or rollback verified")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, OverflowError):
        print("Post-release review blocked; inspect release and source coverage", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
