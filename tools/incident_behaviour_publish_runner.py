#!/usr/bin/env python3
"""Opt-in daily publication of server-computed rule-volume observations; no review or incident rights."""
import argparse
import base64
import hashlib
import json
import os
import sqlite3
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid
import fcntl
from pathlib import Path

from incident_analytics_runner import NoRedirect, epoch, unique_json, utc
from incident_rule_behaviour_runner import DAY, assess, canonical, config, instant, next_day, open_state

ROUTE = "/_plugins/_setup/incident-behaviour/observations/publish"


def digest(*fields):
    result = hashlib.sha256()
    for field in fields:
        data = field.encode("utf-8")
        result.update(struct.pack(">I", len(data)))
        result.update(data)
    return result.digest()


def fingerprint(cfg):
    return digest("wazuh-rule-behaviour-scope-v1", cfg["field"], cfg["value"], cfg["rule_uuid"]).hex()


def observation_id(cfg, day):
    data = bytearray(digest("wazuh-rule-behaviour-observation-v1", cfg["username"], fingerprint(cfg), utc(day))[:16])
    data[6] = (data[6] & 15) | 128
    data[8] = (data[8] & 63) | 128
    return str(uuid.UUID(bytes=bytes(data)))


def validate_receipt(cfg, day, receipt, now):
    query = {key: cfg[key] for key in ("field", "value", "rule_uuid")}
    query["day"] = utc(day)
    if not isinstance(receipt, dict) or set(receipt) != {"id", "query", "actor", "model", "observed_at", "coverage",
                                                        "finding_count", "assessment", "recorded"}:
        raise ValueError("Invalid publication receipt shape")
    if receipt["id"] != observation_id(cfg, day) or receipt["query"] != query or receipt["actor"] != cfg["username"] or \
            receipt["model"] != "rule_volume_v2" or receipt["coverage"] != "search_complete_telemetry_unverified" or receipt["recorded"] is not True:
        raise ValueError("Publication receipt identity mismatch")
    # Replayed committed observations may predate this invocation; never demand a fresh scan.
    if not day+DAY+120 <= instant(receipt["observed_at"]) <= now+300:
        raise ValueError("Invalid observation timestamp")
    a = receipt["assessment"]
    expected = assess(a["daily_counts"], a["current_count"])
    if canonical(a) != canonical(expected) or type(receipt["finding_count"]) is not int or \
            receipt["finding_count"] != expected["baseline_total"]+expected["current_count"]:
        raise ValueError("Observation count conservation failed")
    return canonical({"id": receipt["id"], "assessment": expected, "coverage": receipt["coverage"],
                      "observed_at": receipt["observed_at"], "finding_count": receipt["finding_count"],
                      "receipt_sha256": hashlib.sha256(canonical(receipt).encode()).hexdigest()})


def transport(cfg, password):
    if not password or "\r" in password or "\n" in password:
        raise ValueError("Missing credential")
    tls = ssl.create_default_context(cafile=cfg["ca_file"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls), NoRedirect())
    auth = base64.b64encode((cfg["username"] + ":" + password).encode()).decode("ascii")

    def send(query):
        request = urllib.request.Request(cfg["endpoint"]+ROUTE, data=canonical(query).encode(),
                                         headers={"Authorization": "Basic "+auth, "Content-Type": "application/json"}, method="POST")
        try:
            with opener.open(request, timeout=60) as response:
                raw = response.read(16385)
                if len(raw) > 16384:
                    raise ValueError("Oversize publication receipt")
                return unique_json(raw)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError("Publication HTTP failure") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise RuntimeError("Publication unavailable") from None
    return send


def run_due(db, cfg, send, now, emit=print):
    day = next_day(db, cfg)
    if day+DAY > now-120:
        emit("NO_DUE_DAY")
        return 0
    query = {key: cfg[key] for key in ("field", "value", "rule_uuid")}
    query["day"] = utc(day)
    try:
        # The server will replay an existing record even if older than seven days, but will not backfill a new stale one.
        receipt = send(query)
        recorded = validate_receipt(cfg, day, receipt, now)
        db.execute("BEGIN IMMEDIATE")
        if next_day(db, cfg) != day:
            raise ValueError("Concurrent ledger change")
        db.execute("INSERT INTO observations VALUES (?,?)", (day, recorded))
        db.commit()
    except (ValueError, RuntimeError, TypeError, KeyError, OverflowError, sqlite3.Error):
        db.rollback()
        emit("BLOCKED publication; no day advanced")
        return 1
    emit("RECORDED "+utc(day)+" "+receipt["assessment"]["classification"])
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--print-scope", action="store_true", help="Print only approved scope SHA-256; do not contact indexer")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.config.stat().st_size > 16384:
            raise ValueError("Config too large")
        cfg = config(args.config.read_text(encoding="utf-8"))
        if args.print_scope:
            print(fingerprint(cfg))
            return 0
        if args.state is None:
            raise ValueError("Dedicated state required")
        send = transport(cfg, os.environ.pop("WAZUH_BEHAVIOUR_PUBLISH_PASSWORD", ""))
        # Prevent mixing the prior local-only ledger and the shared publication ledger.
        bound = {**cfg, "mode": "shared_observation_v1"}
        with open(str(args.state)+".lock", "a", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            db = open_state(args.state, bound)
            try:
                return run_due(db, bound, send, int(time.time()))
            finally:
                db.close()
    except (OSError, ValueError, TypeError, KeyError, OverflowError, sqlite3.Error):
        print("Publication configuration, lock or state unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
