#!/usr/bin/env python3
"""Opt-in, single-policy daily rule-volume observation ledger; no incident or response writes."""
import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from incident_analytics_runner import NoRedirect, epoch, identity, unique_json, utc

DAY = 86400
MAX_HITS = 2000
FIELDS = {"wazuh.agent.id", "host.id", "host.name", "host.hostname", "host.ip",
          "source.ip", "destination.ip", "user.name", "user.id"}
INDEX = r"(?:\.ds-)?wazuh-findings-v5-[a-z0-9][a-z0-9-]*-[0-9]{6}"
ROUTE = "/_plugins/_setup/incident-behaviour/rule-assess"


def safe(value, limit):
    return isinstance(value, str) and 0 < len(value.encode("utf-16-le")) // 2 <= limit and bool(value.strip()) and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)


def config(raw):
    cfg = unique_json(raw)
    if not isinstance(cfg, dict) or set(cfg) != {"endpoint", "username", "ca_file", "deployment_id", "policy_id",
                                                  "policy_version", "field", "value", "rule_uuid", "first_day"}:
        raise ValueError("Invalid rule behaviour configuration")
    url = urllib.parse.urlsplit(cfg["endpoint"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
        raise ValueError("HTTPS origin only")
    cfg["endpoint"] = cfg["endpoint"].rstrip("/")
    if not safe(cfg["username"], 1024) or ":" in cfg["username"] or cfg["username"].strip() != cfg["username"] or not safe(cfg["ca_file"], 4096):
        raise ValueError("Explicit account and CA required")
    for key in ("deployment_id", "policy_id", "rule_uuid"):
        identity(cfg[key])
    if type(cfg["policy_version"]) is not int or not 1 <= cfg["policy_version"] <= 2147483647:
        raise ValueError("Invalid policy version")
    value, field = cfg["value"], cfg["field"]
    if field not in FIELDS or not safe(value, 256) or value != value.strip():
        raise ValueError("Exact entity scope required")
    if field.endswith(".ip") and str(ipaddress.IPv4Address(value)) != value:
        raise ValueError("Canonical IPv4 required")
    start = epoch(cfg["first_day"])
    if start % DAY or start < epoch("2000-01-29T00:00:00Z") or start + DAY >= epoch("2100-01-01T00:00:00Z"):
        raise ValueError("Invalid first UTC day")
    return cfg


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def assess(daily, current):
    if not isinstance(daily, list) or len(daily) != 28 or any(type(n) is not int or not 0 <= n <= MAX_HITS for n in daily + [current]):
        raise ValueError("Invalid daily counts")
    total, active = sum(daily), sum(n > 0 for n in daily)
    if total + current > MAX_HITS:
        raise ValueError("Population cap exceeded")
    maximum = max(daily[::7])
    ordered = sorted(daily)
    median2 = ordered[13] + ordered[14]
    deviations = sorted(abs(2*n - median2) for n in ordered)
    mad4 = deviations[13] + deviations[14]
    threshold = max(5, maximum+3, (2*total+27)//28, (2*median2+3*mad4+3)//4)
    classification = ("newly_observed" if current else "no_observed_activity") if not total else (
        "sparse_baseline" if active < 7 else "elevated_rule_volume" if current >= threshold else "within_volume_threshold")
    return dict(daily_counts=daily, baseline_total=total, active_days=active, same_weekday_maximum=maximum,
                median_times_two=median2, mad_times_four=mad4, threshold=threshold, current_count=current, classification=classification)


def instant(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", value):
        raise ValueError("Invalid UTC observation")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def validate(report, cfg, day, now):
    query = {key: cfg[key] for key in ("field", "value", "rule_uuid")}
    query["day"] = utc(day)
    if not isinstance(report, dict) or set(report) != {"scope", "model", "query", "baseline_from", "until", "finding_count",
                                                        "assessment", "current_sample", "coverage", "actor", "observed_at"}:
        raise ValueError("Invalid report shape")
    if report["scope"] != "caller_visible_rule_finding_scan" or report["model"] != "rule_volume_v2" or report["coverage"] != "search_complete_telemetry_unverified" or report["query"] != query or report["actor"] != cfg["username"] or report["baseline_from"] != utc(day-28*DAY) or report["until"] != utc(day+DAY):
        raise ValueError("Mismatched report identity")
    at = instant(report["observed_at"])
    if at < day+DAY+120 or not now-300 <= at <= now+300:
        raise ValueError("Stale or invalid observation time")
    a = report["assessment"]
    expected = assess(a["daily_counts"], a["current_count"])
    if canonical(expected) != canonical(a) or type(report["finding_count"]) is not int or report["finding_count"] != expected["baseline_total"]+expected["current_count"]:
        raise ValueError("Count conservation failed")
    sample = report["current_sample"]
    if not isinstance(sample, list) or len(sample) != min(20, expected["current_count"]):
        raise ValueError("Invalid sample size")
    seen = set()
    for row in sample:
        if not isinstance(row, dict) or set(row) != {"index", "document_id", "timestamp"} or not safe(row["index"], 255) or not re.fullmatch(INDEX, row["index"]) or not safe(row["document_id"], 512) or not day <= instant(row["timestamp"]) < day+DAY:
            raise ValueError("Invalid sampled reference")
        key = (row["index"], row["document_id"])
        if key in seen:
            raise ValueError("Duplicate sample")
        seen.add(key)
    # Do not persist the finding sample; hash binds the observed response but is not a signature.
    return canonical({"assessment": expected, "coverage": report["coverage"], "observed_at": report["observed_at"],
                      "finding_count": report["finding_count"], "response_sha256": hashlib.sha256(canonical(report).encode()).hexdigest()})


def transport(cfg, password):
    if not password or "\r" in password or "\n" in password:
        raise ValueError("Missing credential")
    tls = ssl.create_default_context(cafile=cfg["ca_file"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls), NoRedirect())
    auth = base64.b64encode((cfg["username"] + ":" + password).encode()).decode("ascii")
    def send(query):
        req = urllib.request.Request(cfg["endpoint"] + ROUTE, data=canonical(query).encode(),
                                     headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"}, method="POST")
        try:
            with opener.open(req, timeout=45) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise ValueError("Oversize report")
                return unique_json(raw)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError("Indexer HTTP failure") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise RuntimeError("Indexer unavailable") from None
    return send


def open_state(path, cfg):
    db = sqlite3.connect(path, timeout=5)
    try:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS scope (slot INTEGER PRIMARY KEY CHECK(slot=1), definition TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS observations (day INTEGER PRIMARY KEY, receipt TEXT NOT NULL)")
        row = db.execute("SELECT definition FROM scope WHERE slot=1").fetchone()
        if row is None:
            if db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]:
                raise ValueError("Orphan observation history")
            db.execute("INSERT INTO scope VALUES (1,?)", (canonical(cfg),))
            db.commit()
        elif row[0] != canonical(cfg):
            raise ValueError("State bound to different policy configuration")
        return db
    except Exception:
        db.close()
        raise


def next_day(db, cfg):
    start = epoch(cfg["first_day"])
    count, minimum, maximum, invalid = db.execute(
        "SELECT COUNT(*),MIN(day),MAX(day),SUM(CASE WHEN day%86400!=0 THEN 1 ELSE 0 END) FROM observations").fetchone()
    if count and (minimum != start or invalid or maximum != start+(count-1)*DAY):
        raise ValueError("Noncontiguous observation ledger")
    return start+count*DAY


def run_due(db, cfg, send, now, emit=print):
    day = next_day(db, cfg)
    if day+DAY > now-120:
        emit("NO_DUE_DAY")
        return 0
    if day < now-7*DAY:
        emit("BLOCKED historical gap; operator review required")
        return 1
    query = {key: cfg[key] for key in ("field", "value", "rule_uuid")}
    query["day"] = utc(day)
    try:
        report = send(query)
        receipt = validate(report, cfg, day, now)
        # Single insert transaction; a retry after commit observes the next day, not another write for this day.
        db.execute("BEGIN IMMEDIATE")
        if next_day(db, cfg) != day:
            raise ValueError("Concurrent ledger change")
        db.execute("INSERT INTO observations VALUES (?,?)", (day, receipt))
        db.commit()
    except (ValueError, RuntimeError, TypeError, KeyError, OverflowError, sqlite3.Error):
        db.rollback()
        emit("BLOCKED observation; no day advanced")
        return 1
    emit("RECORDED " + utc(day) + " " + report["assessment"]["classification"])
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.config.stat().st_size > 16384:
            raise ValueError("Config too large")
        cfg = config(args.config.read_text(encoding="utf-8"))
        send = transport(cfg, os.environ.pop("WAZUH_BEHAVIOUR_PASSWORD", ""))
        with open(str(args.state)+".lock", "a", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            db = open_state(args.state, cfg)
            try:
                return run_due(db, cfg, send, int(time.time()))
            finally:
                db.close()
    except (OSError, ValueError, TypeError, KeyError, OverflowError, sqlite3.Error):
        print("Behaviour configuration, lock or state unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
