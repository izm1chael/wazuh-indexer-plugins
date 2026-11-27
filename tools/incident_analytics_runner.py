#!/usr/bin/env python3
"""Opt-in, single-host scheduler for approved Wazuh native-finding analytics windows.

Invoke periodically (e.g. systemd timer) with a protected configuration and credential.
No automatic enablement, no service-account impersonation, no TLS bypass.
"""
import argparse
import base64
import datetime as dt
import fcntl
import json
import os
import re
import ssl
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = "/_plugins/_setup/incident-analytics/"
MAX_WINDOWS = 10
GRACE = 120


def utc(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError("Expected canonical UTC time")
    result = int(dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp())
    if utc(result) != value or not 946684800 <= result <= 4102444800:
        raise ValueError("UTC time outside supported range")
    return result


def identity(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("Canonical UUID required")
    return value


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, val in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = val
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON constant")))


def load_config(raw):
    config = unique_json(raw)
    if not isinstance(config, dict) or set(config) != {"endpoint", "deployment_id", "username", "ca_file", "policies"}:
        raise ValueError("Invalid scheduler configuration")
    endpoint = urllib.parse.urlsplit(config["endpoint"])
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment:
        raise ValueError("HTTPS origin only")
    identity(config["deployment_id"])
    user = config["username"]
    if not isinstance(user, str) or not user or len(user) > 1024 or user.strip() != user or ":" in user or any(ord(ch) < 32 for ch in user):
        raise ValueError("Invalid service account")
    if not isinstance(config["ca_file"], str) or not config["ca_file"]:
        raise ValueError("Explicit CA file required")
    policies = config["policies"]
    if not isinstance(policies, list) or not 1 <= len(policies) <= 20:
        raise ValueError("One to twenty policies required")
    seen = set()
    for policy in policies:
        if not isinstance(policy, dict) or set(policy) != {"policy_id", "policy_version", "window_minutes", "first_window_start"}:
            raise ValueError("Invalid policy schedule")
        key = (identity(policy["policy_id"]), policy["policy_version"])
        version, minutes = policy["policy_version"], policy["window_minutes"]
        if type(version) is not int or not 1 <= version <= 2147483647 or type(minutes) is not int or not 5 <= minutes <= 1440 or key in seen:
            raise ValueError("Invalid or duplicate schedule")
        seen.add(key)
        if epoch(policy["first_window_start"]) % (minutes * 60):
            raise ValueError("Schedule start must align to policy UTC windows")
    return config


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def transport(config, password):
    if not password or "\n" in password or "\r" in password:
        raise ValueError("Missing or invalid scheduler credential")
    tls = ssl.create_default_context(cafile=config["ca_file"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls), NoRedirect())
    auth = base64.b64encode((config["username"] + ":" + password).encode()).decode("ascii")
    origin = config["endpoint"].rstrip("/")

    def request(operation, payload):
        if operation not in ("status", "execute"):
            raise ValueError("Unsupported operation")
        req = urllib.request.Request(origin + ROOT + operation, data=json.dumps(payload).encode(),
                                     headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"}, method="POST")
        try:
            with opener.open(req, timeout=150) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise ValueError("Oversize receipt")
                return unique_json(raw)
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise RuntimeError("Indexer returned HTTP " + str(code)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise RuntimeError("Indexer request unavailable") from None
    return request


def run_id(deployment, payload):
    import hashlib
    import struct
    digest = hashlib.sha256()
    for value in ("wazuh-analytics-window-v1", deployment, payload["policy_id"], str(payload["policy_version"]), payload["from"], payload["until"]):
        data = value.encode()
        digest.update(struct.pack(">I", len(data)))
        digest.update(data)
    return digest.hexdigest()


def validate_receipt(receipt, config, payload):
    if not isinstance(receipt, dict) or type(receipt.get("policy_version")) is not int or any(receipt.get(key) != val for key, val in payload.items()) or receipt.get("run_id") != run_id(config["deployment_id"], payload):
        raise ValueError("Mismatched analytics receipt")
    base = set(payload) | {"run_id", "state"}
    state = receipt.get("state")
    if state == "not_recorded":
        if set(receipt) != base:
            raise ValueError("Unexpected unrecorded receipt")
        return state
    if state not in ("reserved", "completed") or set(receipt) != base | {"finding_count", "group_count", "below_threshold", "actor", "reserved_at", "completed_at"} or receipt.get("actor") != config["username"]:
        raise ValueError("Invalid analytics receipt")
    findings, groups, below = (receipt.get(key) for key in ("finding_count", "group_count", "below_threshold"))
    if any(type(x) is not int for x in (findings, groups, below)) or not 0 <= findings <= 100 or not 0 <= groups <= 20 or not 0 <= below <= findings or groups * 2 > findings - below or (groups == 0) != (findings == below):
        raise ValueError("Receipt count mismatch")
    def receipt_time(value):
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", value):
            raise ValueError("Invalid receipt timestamp")
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    reserved = receipt_time(receipt.get("reserved_at"))
    if reserved < epoch(payload["until"]) + GRACE or (state == "reserved" and receipt.get("completed_at") is not None) or (state == "completed" and receipt_time(receipt.get("completed_at")) < reserved):
        raise ValueError("Invalid receipt chronology")
    return state


def open_state(path):
    # The state directory must be operator-controlled; SQLite contains no credential or finding data.
    db = sqlite3.connect(path, timeout=5)
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS cursors (deployment TEXT, policy TEXT, version INTEGER, minutes INTEGER, first_start INTEGER, next_start INTEGER, PRIMARY KEY(deployment,policy,version))")
    db.execute("CREATE TABLE IF NOT EXISTS scheduler_position (deployment TEXT PRIMARY KEY, position INTEGER NOT NULL)")
    db.commit()
    return db


def run_due(config, db, request, now, budget=MAX_WINDOWS, emit=print):
    """Advance only after a matching server completion. A gap or failure blocks that policy."""
    if not 1 <= budget <= MAX_WINDOWS:
        raise ValueError("Invalid run budget")
    processed = 0
    failed = False
    policies = config["policies"]
    position = db.execute("SELECT position FROM scheduler_position WHERE deployment=?", (config["deployment_id"],)).fetchone()
    start_position = (position[0] if position else 0) % len(policies)
    for offset in range(len(policies)):
        if processed >= budget:
            break
        index = (start_position + offset) % len(policies)
        policy = policies[index]
        db.execute("INSERT INTO scheduler_position VALUES (?,?) ON CONFLICT(deployment) DO UPDATE SET position=excluded.position",
                   (config["deployment_id"], (index + 1) % len(policies)))
        db.commit()
        pid, version, minutes = policy["policy_id"], policy["policy_version"], policy["window_minutes"]
        start = epoch(policy["first_window_start"])
        key = (config["deployment_id"], pid, version)
        row = db.execute("SELECT minutes,first_start,next_start FROM cursors WHERE deployment=? AND policy=? AND version=?", key).fetchone()
        if row is None:
            db.execute("INSERT INTO cursors VALUES (?,?,?,?,?,?)", (*key, minutes, start, start))
            db.commit()
            cursor = start
        else:
            if row[:2] != (minutes, start) or row[2] < start or (row[2] - start) % (minutes * 60):
                emit("BLOCKED schedule changed or corrupt cursor: " + pid + ":" + str(version))
                failed = True
                continue
            cursor = row[2]
        if cursor + minutes * 60 <= now - GRACE and processed < budget:
            until = cursor + minutes * 60
            payload = {"policy_id": pid, "policy_version": version, "from": utc(cursor), "until": utc(until)}
            processed += 1
            try:
                state = validate_receipt(request("status", payload), config, payload)
                if state != "completed":
                    if cursor < now - 7 * 86400:
                        raise RuntimeError("Window outside automatic backfill limit; operator reconciliation required")
                    state = validate_receipt(request("execute", payload), config, payload)
                if state != "completed":
                    raise RuntimeError("Execution not completed")
                update = db.execute("UPDATE cursors SET next_start=? WHERE deployment=? AND policy=? AND version=? AND next_start=?",
                                    (until, *key, cursor))
                if update.rowcount != 1:
                    db.rollback()
                    raise RuntimeError("Cursor conflict")
                db.commit()
                emit("COMPLETED " + pid + ":" + str(version) + " " + payload["from"])
            except (RuntimeError, ValueError, sqlite3.Error) as exc:
                db.rollback()
                # Do not emit response bodies, credentials, source values or arbitrary exception text.
                emit("BLOCKED " + pid + ":" + str(version) + " " + payload["from"] + " (" + type(exc).__name__ + ")")
                failed = True
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.config.stat().st_size > 65536:
            raise ValueError("Config too large")
        config = load_config(args.config.read_text(encoding="utf-8"))
        password = os.environ.pop("WAZUH_ANALYTICS_PASSWORD", "")
        request = transport(config, password)
        with open(str(args.state) + ".lock", "a", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("Analytics runner already active", file=sys.stderr)
                return 1
            db = open_state(args.state)
            try:
                return run_due(config, db, request, int(time.time()))
            finally:
                db.close()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        print("Analytics runner configuration or state unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
