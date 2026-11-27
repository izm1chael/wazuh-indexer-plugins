#!/usr/bin/env python3
"""Opt-in bounded incident automation sweep. No source telemetry or endpoint actions."""
import argparse
import base64
import fcntl
import json
import os
import re
import sqlite3
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from incident_analytics_runner import NoRedirect, identity, unique_json

ROOT = "/_plugins/_setup/incident-automation/tick"
PAGE = 10
MAX_PAGES = 3


def config(raw):
    value = unique_json(raw)
    if not isinstance(value, dict) or set(value) != {"endpoint", "username", "ca_file", "policy_id", "policy_version", "fingerprint"}:
        raise ValueError("Invalid automation configuration")
    endpoint = urllib.parse.urlsplit(value["endpoint"])
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment:
        raise ValueError("HTTPS origin required")
    user = value["username"]
    if not isinstance(user, str) or not user or user.strip() != user or len(user) > 1024 or ":" in user or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in user):
        raise ValueError("Invalid account")
    if not isinstance(value["ca_file"], str) or not value["ca_file"]:
        raise ValueError("Explicit CA required")
    identity(value["policy_id"])
    if type(value["policy_version"]) is not int or not 1 <= value["policy_version"] <= 2147483647:
        raise ValueError("Invalid version")
    if not isinstance(value["fingerprint"], str) or not re.fullmatch("[a-f0-9]{64}", value["fingerprint"]):
        raise ValueError("Exact approved fingerprint required")
    value["endpoint"] = value["endpoint"].rstrip("/")
    return value


def transport(cfg, password):
    if not password or "\r" in password or "\n" in password:
        raise ValueError("Missing credential")
    tls = ssl.create_default_context(cafile=cfg["ca_file"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls), NoRedirect())
    auth = base64.b64encode((cfg["username"] + ":" + password).encode()).decode("ascii")

    def send(payload):
        request = urllib.request.Request(cfg["endpoint"] + ROOT, data=json.dumps(payload).encode("utf-8"),
                                        headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"}, method="POST")
        try:
            with opener.open(request, timeout=150) as response:
                raw = response.read(16385)
                if len(raw) > 16384:
                    raise ValueError("Oversize sweep response")
                return unique_json(raw)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError("Automation HTTP failure") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise RuntimeError("Automation request unavailable") from None
    return send


def validate_page(body, cfg, after):
    fields = {"policy_id", "policy_version", "fingerprint", "actor", "scanned", "applied",
              "no_change", "skipped", "pending", "failed", "next_after"}
    if not isinstance(body, dict) or set(body) != fields or body["actor"] != cfg["username"] or type(body["policy_version"]) is not int:
        raise ValueError("Invalid page receipt")
    if any(body[key] != cfg[key] for key in ("policy_id", "policy_version", "fingerprint")):
        raise ValueError("Mismatched approval receipt")
    counts = [body[key] for key in ("applied", "no_change", "skipped", "pending", "failed")]
    if any(type(n) is not int or not 0 <= n <= PAGE for n in counts + [body["scanned"]]) or sum(counts) != body["scanned"]:
        raise ValueError("Page count mismatch")
    cursor = body["next_after"]
    if (cursor is None) != (body["scanned"] < PAGE):
        raise ValueError("Cursor coverage mismatch")
    if cursor is not None and (identity(cursor) != cursor or (after is not None and cursor <= after)):
        raise ValueError("Non-advancing cursor")
    return cursor


def open_state(path, cfg):
    db = sqlite3.connect(path, timeout=5)
    try:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS automation_cursor (slot INTEGER PRIMARY KEY CHECK(slot=1), scope TEXT NOT NULL, after_id TEXT)")
        scope = json.dumps({key: cfg[key] for key in ("endpoint", "username", "policy_id", "policy_version", "fingerprint")}, sort_keys=True)
        row = db.execute("SELECT scope, after_id FROM automation_cursor WHERE slot=1").fetchone()
        if row is None:
            db.execute("INSERT INTO automation_cursor VALUES (1,?,NULL)", (scope,))
            db.commit()
        elif row[0] != scope:
            raise ValueError("State belongs to another approved rule set or endpoint")
        elif row[1] is not None:
            identity(row[1])
        return db
    except Exception:
        db.close()
        raise


def sweep(cfg, db, send, budget=MAX_PAGES, emit=print):
    """Only advance after validated page; failed/pending cases are revisited on next sweep."""
    if type(budget) is not int or not 1 <= budget <= MAX_PAGES:
        raise ValueError("Invalid sweep budget")
    row = db.execute("SELECT after_id FROM automation_cursor WHERE slot=1").fetchone()
    if row is None:
        raise ValueError("Missing cursor")
    after = row[0]
    incomplete = False
    for _ in range(budget):
        payload = {key: cfg[key] for key in ("policy_id", "policy_version", "fingerprint")}
        payload["after"] = after
        try:
            body = send(payload)
            next_after = validate_page(body, cfg, after)
            updated = db.execute("UPDATE automation_cursor SET after_id=? WHERE slot=1 AND after_id IS ?", (next_after, after))
            if updated.rowcount != 1:
                raise RuntimeError("Cursor changed")
            db.commit()
        except (ValueError, RuntimeError, sqlite3.Error, TypeError, KeyError):
            db.rollback()
            emit("BLOCKED automation page; cursor retained")
            return 1
        emit("PAGE " + " ".join(key + "=" + str(body[key]) for key in ("scanned", "applied", "no_change", "skipped", "pending", "failed")))
        incomplete = incomplete or body["failed"] > 0 or body["pending"] > 0
        after = next_after
        if after is None:
            break
    return 1 if incomplete else 0


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
        send = transport(cfg, os.environ.pop("WAZUH_AUTOMATION_PASSWORD", ""))
        with open(str(args.state) + ".lock", "a", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("Automation runner already active", file=sys.stderr)
                return 1
            db = open_state(args.state, cfg)
            try:
                return sweep(cfg, db, send)
            finally:
                db.close()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        print("Automation configuration or state unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
