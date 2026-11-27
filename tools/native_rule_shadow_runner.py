#!/usr/bin/env python3
"""Opt-in prospective closed-window replay against pinned Test and Custom content; no content writes."""
import argparse
import datetime as dt
import fcntl
import os
import sqlite3
import sys
import time
from pathlib import Path

import native_rule_replay as replay
from incident_analytics_runner import unique_json


def config(raw):
    value = unique_json(raw)
    if not isinstance(value, dict) or set(value) != {"replay", "first_window", "window_seconds"}:
        raise ValueError("Invalid shadow policy")
    start = replay.utc(value["first_window"])
    seconds = value["window_seconds"]
    if type(seconds) is not int or not 300 <= seconds <= 3600 or 86400 % seconds or int(start.timestamp()) % seconds or start.microsecond or value["first_window"] != iso(start):
        raise ValueError("Invalid UTC window alignment")
    # No historical bootstrap masquerading as a prospective run.
    core = value["replay"]
    if not isinstance(core, dict) or "from" in core or "until" in core:
        raise ValueError("Expected pinned replay scope without window")
    cfg = replay.config(replay.canonical({**core, "from": iso(start), "until": iso(start+dt.timedelta(seconds=seconds))}))
    if not cfg["expected_test_sha256"] or not cfg["expected_custom_sha256"]:
        raise ValueError("Both content fingerprints must be pinned")
    return {"replay": {k: v for k, v in cfg.items() if k not in ("from", "until")},
            "first_window": iso(start), "window_seconds": seconds}


def iso(value):
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def open_state(path, cfg, now):
    db = sqlite3.connect(path, timeout=5)
    try:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS scope (slot INTEGER PRIMARY KEY CHECK(slot=1), definition TEXT NOT NULL, registered INTEGER NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS windows (start INTEGER PRIMARY KEY, receipt TEXT NOT NULL)")
        row = db.execute("SELECT definition,registered FROM scope WHERE slot=1").fetchone()
        start = int(replay.utc(cfg["first_window"]).timestamp())
        if row is None:
            if start <= now or db.execute("SELECT COUNT(*) FROM windows").fetchone()[0]:
                raise ValueError("First prospective window must begin after registration")
            db.execute("INSERT INTO scope VALUES (1,?,?)", (replay.canonical(cfg), now))
            db.commit()
        elif row[0] != replay.canonical(cfg) or row[1] >= start:
            raise ValueError("Shadow state belongs to another policy or nonprospective registration")
        return db
    except Exception:
        db.close()
        raise


def next_window(db, cfg):
    first = int(replay.utc(cfg["first_window"]).timestamp())
    width = cfg["window_seconds"]
    count, minimum, maximum, invalid = db.execute(
        "SELECT COUNT(*),MIN(start),MAX(start),SUM(CASE WHEN start%?!=0 THEN 1 ELSE 0 END) FROM windows", (width,)).fetchone()
    if count and (minimum != first or maximum != first+(count-1)*width or invalid):
        raise ValueError("Noncontiguous shadow ledger")
    return first+count*width


def tick(db, cfg, now, send, run=replay.replay):
    start = next_window(db, cfg)
    end = start+cfg["window_seconds"]
    if end > now-120:
        return "NO_DUE_WINDOW"
    if end < now-86400:
        raise ValueError("Stale prospective window; review coverage before creating a new campaign")
    query = {**cfg["replay"], "from": iso(dt.datetime.fromtimestamp(start, dt.timezone.utc)),
             "until": iso(dt.datetime.fromtimestamp(end, dt.timezone.utc))}
    receipt = run(send, query, dt.datetime.fromtimestamp(now, dt.timezone.utc))
    if receipt["scope"]["from"] != query["from"] or receipt["scope"]["until"] != query["until"] or \
            receipt["test_sha256"] != query["expected_test_sha256"] or receipt["custom_sha256"] != query["expected_custom_sha256"] or \
            receipt["promotion_authorized"] is not False:
        raise ValueError("Receipt scope changed")
    # Local-only receipt ledger; no automatic promotion and no raw event source.
    try:
        db.execute("BEGIN IMMEDIATE")
        if next_window(db, cfg) != start:
            raise ValueError("Concurrent shadow window")
        db.execute("INSERT INTO windows VALUES (?,?)", (start, replay.canonical(receipt)))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return "RECORDED_WINDOW "+query["from"]


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
        now = int(time.time())
        with open(str(args.state)+".lock", "a", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            db = open_state(args.state, cfg, now)
            try:
                send = replay.transport(cfg["replay"], os.environ.pop("WAZUH_NATIVE_REPLAY_PASSWORD", ""))
                print(tick(db, cfg, now, send))
            finally:
                db.close()
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, OverflowError, sqlite3.Error):
        print("Shadow window blocked; no promotion authorized", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
