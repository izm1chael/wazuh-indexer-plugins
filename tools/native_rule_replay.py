#!/usr/bin/env python3
"""Native Content Manager paired detection replay. Read-only; never promotes or writes content."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
from pathlib import Path

from incident_analytics_runner import NoRedirect, unique_json

ROOT = "/_plugins/_content_manager"
MAX_EVENTS = 100
MAX_RULES = 200
UUID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
EVENT_INDEX = re.compile(r"(?:\.ds-)?wazuh-events-v5-[a-z0-9][a-z0-9-]*-[0-9]{6}")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def utc(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", value):
        raise ValueError("Expected UTC instant")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def literal(v, limit=256):
    return isinstance(v, str) and 0 < len(v) <= limit and v.strip() == v and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in v)


def identity(v):
    if not isinstance(v, str) or not UUID.fullmatch(v):
        raise ValueError("Expected canonical UUID")
    return v


def config(raw):
    cfg = unique_json(raw)
    if not isinstance(cfg, dict) or set(cfg) != {"endpoint", "username", "ca_file", "integration", "cluster", "space", "dataset", "from", "until", "expected_test_sha256", "expected_custom_sha256"}:
        raise ValueError("Invalid replay configuration")
    url = urllib.parse.urlsplit(cfg["endpoint"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
        raise ValueError("HTTPS origin only")
    cfg["endpoint"] = cfg["endpoint"].rstrip("/")
    for key in ("username", "ca_file", "cluster", "space", "dataset"):
        if not literal(cfg[key], 4096 if key == "ca_file" else 256):
            raise ValueError("Invalid replay scope")
    if ":" in cfg["username"]:
        raise ValueError("Invalid account")
    identity(cfg["integration"])
    start, end = utc(cfg["from"]), utc(cfg["until"])
    if any(not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", cfg[k]) for k in ("from", "until")) or not dt.timedelta(0) < end-start <= dt.timedelta(days=1):
        raise ValueError("Expected bounded closed interval")
    for key in ("expected_test_sha256", "expected_custom_sha256"):
        if cfg[key] is not None and (not isinstance(cfg[key], str) or not re.fullmatch(r"[a-f0-9]{64}", cfg[key])):
            raise ValueError("Invalid content fingerprint")
    return cfg


def transport(cfg, password):
    if not password or "\r" in password or "\n" in password:
        raise ValueError("Credential required")
    context = ssl.create_default_context(cafile=cfg["ca_file"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
    auth = base64.b64encode((cfg["username"]+":"+password).encode()).decode("ascii")
    deadline = time.monotonic()+300

    def send(method, path, body=None):
        left = deadline-time.monotonic()
        if left <= 0:
            raise ValueError("Replay time budget exceeded")
        request = urllib.request.Request(cfg["endpoint"]+path,
            data=None if body is None else canonical(body).encode(), method=method,
            headers={"Authorization": "Basic "+auth, "Content-Type": "application/json"})
        try:
            with opener.open(request, timeout=min(15, left)) as response:
                raw = response.read(16*1024*1024+1)
                if len(raw) > 16*1024*1024:
                    raise ValueError("Response exceeds replay budget")
                return unique_json(raw)
        except (OSError, TimeoutError, urllib.error.URLError):
            raise RuntimeError("Native replay request failed") from None
    return send


def search(send, index, filters, cap, fields=None):
    body = {"size": cap+1, "track_total_hits": True, "timeout": "10s",
            "seq_no_primary_term": True, "query": {"bool": {"filter": filters}}}
    if fields is not None:
        body["_source"] = fields
    result = send("POST", "/"+index+"/_search?allow_partial_search_results=false&ignore_unavailable=false&allow_no_indices=false&expand_wildcards=open", body)
    hits = result["hits"]["hits"]
    total = result["hits"]["total"]
    if result.get("timed_out") is not False or result.get("terminated_early") is True or result["_shards"]["failed"] != 0 or type(result["_shards"]["total"]) is not int or result["_shards"]["total"] < 1 or \
            total["relation"] != "eq" or type(total["value"]) is not int or total["value"] != len(hits) or len(hits) > cap:
        raise ValueError("Incomplete or over-cap search")
    seen = set()
    for hit in hits:
        key = (hit["_index"], hit["_id"])
        if key in seen or not isinstance(hit["_source"], dict) or type(hit["_seq_no"]) is not int or type(hit["_primary_term"]) is not int:
            raise ValueError("Invalid search identity")
        seen.add(key)
    return sorted(hits, key=lambda h: (h["_index"], h["_id"]))


def scalar(source, field):
    parts = field.split(".")
    node = source
    for n, part in enumerate(parts):
        if not isinstance(node, dict):
            raise ValueError("Ambiguous source")
        remaining = ".".join(parts[n:])
        if n < len(parts)-1 and remaining in node:
            if part in node:
                raise ValueError("Mixed source representation")
            return node[remaining]
        node = node.get(part)
    return node


def content_details(send, cfg, space):
    filters = [{"term": {"space.name": space}}, {"term": {"document.id": cfg["integration"]}}]
    integration = search(send, "wazuh-threatintel-integrations", filters, 1)
    if len(integration) != 1:
        raise ValueError("Integration must exist in both native spaces")
    source = integration[0]["_source"]
    if scalar(source, "space.name") != space or scalar(source, "document.id") != cfg["integration"]:
        raise ValueError("Integration source identity mismatch")
    rules = source["document"]["rules"]
    if not isinstance(rules, list) or len(rules) > MAX_RULES or len(set(rules)) != len(rules):
        raise ValueError("Invalid integration membership")
    for rule in rules:
        identity(rule)
    hits = search(send, "wazuh-threatintel-rules", [{"term": {"space.name": space}},
                  {"terms": {"document.id": rules}}], MAX_RULES) if rules else []
    enabled = set()
    seen = set()
    for hit in hits:
        doc = hit["_source"]
        rule = identity(scalar(doc, "document.id"))
        if scalar(doc, "space.name") != space or rule not in rules or rule in seen:
            raise ValueError("Invalid rule membership")
        seen.add(rule)
        flag = scalar(doc, "document.enabled")
        if type(flag) is not bool:
            raise ValueError("Missing rule enabled state")
        if flag:
            enabled.add(rule)
    if seen != set(rules):
        raise ValueError("Incomplete integration rule visibility")
    # Include exact content and sequence metadata. No claim to hash compiled mappings or engine state.
    return {"sha256": sha({"integration": integration, "rules": hits}), "enabled": enabled,
            "integration": source["document"],
            "rules": {scalar(hit["_source"], "document.id"): hit["_source"]["document"] for hit in hits}}


def content_snapshot(send, cfg, space):
    details = content_details(send, cfg, space)
    return details["sha256"], details["enabled"]


def events(send, cfg):
    terms = {"wazuh.cluster.name": cfg["cluster"], "wazuh.space.name": cfg["space"], "event.dataset": cfg["dataset"]}
    hits = search(send, "wazuh-events-v5*", [{"term": {k: v}} for k, v in terms.items()]+[
        {"range": {"@timestamp": {"gte": cfg["from"], "lt": cfg["until"]}}}], MAX_EVENTS)
    rows = []
    for hit in hits:
        source = hit["_source"]
        if not EVENT_INDEX.fullmatch(hit["_index"]) or not literal(hit["_id"], 512) or any(scalar(source, k) != v for k, v in terms.items()) or \
                not utc(cfg["from"]) <= utc(scalar(source, "@timestamp")) < utc(cfg["until"]):
            raise ValueError("Event source scope mismatch")
        if len(canonical(source).encode()) > 65536:
            raise ValueError("Oversize event")
        rows.append({"index": hit["_index"], "id": hit["_id"], "source_sha256": sha(source), "source": source})
    # Empty exact searches are recorded as no observed events, not detection qualification.
    return rows


def matched(response, expected):
    if not isinstance(response, dict) or response.get("status") != 200 or not isinstance(response.get("message"), dict):
        raise ValueError("Native detection unavailable")
    data = response["message"]
    # RC2 may report success with zero rules on fetch failure. Compare to the independently read enabled set.
    if data.get("status") != "success" or type(data.get("rules_evaluated")) is not int or data["rules_evaluated"] != len(expected) or \
            type(data.get("rules_matched")) is not int or not isinstance(data.get("matches"), list) or data["rules_matched"] != len(data["matches"]):
        raise ValueError("Incomplete native evaluation")
    ids = [identity(row["rule"]["id"]) for row in data["matches"]]
    if len(set(ids)) != len(ids) or not set(ids) <= expected:
        raise ValueError("Unexpected native rule identity")
    return set(ids)


def replay(send, cfg, now, pace=lambda: time.sleep(0.1)):
    if utc(cfg["until"]) > now-dt.timedelta(seconds=120):
        raise ValueError("Comparison interval not completed")
    test = content_snapshot(send, cfg, "test")
    custom = content_snapshot(send, cfg, "custom")
    if not test[1] or test[0] != cfg["expected_test_sha256"] or custom[0] != cfg["expected_custom_sha256"]:
        raise ValueError("Content differs from reviewed fingerprints")
    preview = send("GET", ROOT+"/promote?space=test")
    rows = events(send, cfg)
    results = []
    for row in rows:
        base = matched(send("POST", ROOT+"/logtest/detection", {"space": "custom", "integration": cfg["integration"], "input": row["source"]}), custom[1])
        pace()
        candidate = matched(send("POST", ROOT+"/logtest/detection", {"space": "test", "integration": cfg["integration"], "input": row["source"]}), test[1])
        pace()
        results.append({k: row[k] for k in ("index", "id", "source_sha256")} | {
            "baseline": sorted(base), "candidate": sorted(candidate), "gained": sorted(candidate-base), "lost": sorted(base-candidate)})
    if content_snapshot(send, cfg, "test") != test or content_snapshot(send, cfg, "custom") != custom or send("GET", ROOT+"/promote?space=test") != preview:
        raise ValueError("Content or promotion preview changed during replay")
    return {"format": "wazuh-native-paired-replay-v1", "scope": {k: cfg[k] for k in ("integration", "cluster", "space", "dataset", "from", "until")},
            "observed_at": now.isoformat(), "test_sha256": test[0], "custom_sha256": custom[0],
            "preview_sha256": sha(preview), "event_count": len(results),
            "baseline_matches": sum(len(r["baseline"]) for r in results), "candidate_matches": sum(len(r["candidate"]) for r in results),
            "gained_matches": sum(len(r["gained"]) for r in results), "lost_matches": sum(len(r["lost"]) for r in results),
            "rows": results, "coverage": "exact_search_telemetry_unverified", "promotion_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--fingerprints", action="store_true", help="Inspect current content hashes without replay")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.config.stat().st_size > 16384:
            raise ValueError("Oversize configuration")
        cfg = config(args.config.read_text(encoding="utf-8"))
        send = transport(cfg, os.environ.pop("WAZUH_NATIVE_REPLAY_PASSWORD", ""))
        if args.fingerprints:
            print(canonical({space+"_sha256": content_snapshot(send, cfg, space)[0] for space in ("test", "custom")}))
            return 0
        if args.output is None:
            raise ValueError("Explicit new receipt path required")
        result = replay(send, cfg, dt.datetime.now(dt.timezone.utc))
        with args.output.open("x", encoding="utf-8") as output:
            output.write(canonical(result)+"\n")
            output.flush()
            os.fsync(output.fileno())
        print("RECORDED paired native replay; no promotion authorized")
        return 0
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, OverflowError):
        print("Replay blocked; no promotion authorized", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
