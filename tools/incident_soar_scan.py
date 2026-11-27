#!/usr/bin/env python3
"""Explicit single-approved-request Wazuh RC2 scan dispatch, never scheduled or retried."""
import argparse
import base64
import datetime as dt
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from incident_analytics_runner import NoRedirect, identity, unique_json

DISPATCH = "/_plugins/_setup/incident-soar/dispatch"
AGENT = re.compile(r"[0-9]{3,8}")


def agent_id(value):
    if not isinstance(value, str) or not AGENT.fullmatch(value) or int(value) == 0:
        raise ValueError("Exact non-manager numeric agent ID required")
    return value


def origin(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("HTTPS origin required")
    return value.rstrip("/")


def config(raw):
    cfg = unique_json(raw)
    fields = {"indexer", "indexer_ca", "indexer_user", "manager", "manager_ca", "manager_user", "manager_id", "agents"}
    if not isinstance(cfg, dict) or set(cfg) != fields:
        raise ValueError("Invalid scan configuration")
    for field in ("indexer", "manager"):
        cfg[field] = origin(cfg[field])
    identity(cfg["manager_id"])
    for key in ("indexer_ca", "manager_ca", "indexer_user", "manager_user"):
        v = cfg[key]
        if not isinstance(v, str) or not v or len(v) > 1024 or v.strip() != v or any(ord(ch) < 32 for ch in v):
            raise ValueError("Invalid account or CA")
    if ":" in cfg["indexer_user"] or ":" in cfg["manager_user"]:
        raise ValueError("Invalid account")
    agents = cfg["agents"]
    if not isinstance(agents, dict) or not 1 <= len(agents) <= 50:
        raise ValueError("Agent allowlist required")
    for agent, enrolled in agents.items():
        agent_id(agent)
        if not isinstance(enrolled, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", enrolled):
            raise ValueError("Exact agent enrollment time required")
        dt.datetime.fromisoformat(enrolled.replace("Z", "+00:00"))
    return cfg


def basic(user, password):
    if not password or "\r" in password or "\n" in password:
        raise ValueError("Credential unavailable")
    return "Basic " + base64.b64encode((user + ":" + password).encode()).decode("ascii")


def client(base, ca):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)), NoRedirect())

    def send(method, path, authorization, payload=None):
        headers = {"Authorization": authorization, "Accept": "application/json"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        request = urllib.request.Request(base + path, method=method, headers=headers, data=data)
        with opener.open(request, timeout=20) as response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError("Oversize response")
            return unique_json(raw)
    return send


def manager_token(body):
    if not isinstance(body, dict) or type(body.get("error")) is not int or body["error"] != 0:
        raise ValueError("Manager authentication rejected")
    data = body.get("data")
    token = data.get("token") if isinstance(data, dict) else None
    if not isinstance(token, str) or len(token) > 8192 or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
        raise ValueError("Invalid manager token")
    return token


def request_body(cfg, incident, response_id, revision, agent, outcome=None):
    identity(incident)
    agent_id(agent)
    if agent not in cfg["agents"]:
        raise ValueError("Agent not approved locally")
    if not isinstance(response_id, str) or not re.fullmatch(re.escape(incident) + r":[1-9][0-9]{0,9}", response_id):
        raise ValueError("Exact response ID required")
    if type(revision) is not int or not 1 <= revision < 2147483647 or int(response_id.split(":")[-1]) > revision:
        raise ValueError("Invalid expected revision")
    if outcome not in (None, "manager_accepted", "dispatch_unknown"):
        raise ValueError("Invalid report")
    return dict(incident_id=incident, expected_revision=revision, response_id=response_id,
                manager_id=cfg["manager_id"], scope=cfg["manager_id"] + ":agent:" + agent, outcome=outcome)


def receipt(body, cfg, payload, now=None):
    keys = {"incident_id", "response_id", "revision", "scope", "state", "actor", "at", "execution_verified"}
    if not isinstance(body, dict) or set(body) != keys or any(body[k] != payload[k] for k in ("incident_id", "response_id", "scope")):
        raise ValueError("Receipt identity mismatch")
    if type(body["revision"]) is not int or body["revision"] != payload["expected_revision"] + 1 or body["actor"] != cfg["indexer_user"] or body["execution_verified"] is not False:
        raise ValueError("Receipt attribution mismatch")
    if body["state"] != (payload["outcome"] or "dispatch_reserved"):
        raise ValueError("Receipt state mismatch")
    at = body["at"]
    if not isinstance(at, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", at):
        raise ValueError("Invalid receipt time")
    instant = dt.datetime.fromisoformat(at.replace("Z", "+00:00"))
    if now is not None and not -5 <= (now - instant).total_seconds() <= 60:
        raise ValueError("Reservation is not fresh")
    return body


def accepted(body, agent):
    # RC2 documented response is command admission, not an execution result.
    if not isinstance(body, dict) or type(body.get("error")) is not int or body["error"] != 0:
        return False
    data = body.get("data")
    return isinstance(data, dict) and data.get("affected_items") == [agent] and type(data.get("total_affected_items")) is int and data["total_affected_items"] == 1 and type(data.get("total_failed_items")) is int and data["total_failed_items"] == 0 and data.get("failed_items") == []


def preflight(body, cfg, agent):
    if not isinstance(body, dict) or type(body.get("error")) is not int or body["error"] != 0:
        return False
    data = body.get("data")
    if not isinstance(data, dict) or type(data.get("total_affected_items")) is not int or data["total_affected_items"] != 1 or type(data.get("total_failed_items")) is not int or data["total_failed_items"] != 0 or data.get("failed_items") != []:
        return False
    rows = data.get("affected_items")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return False
    row = rows[0]
    return row.get("id") == agent and row.get("dateAdd") == cfg["agents"][agent] and row.get("status") == "active" and isinstance(row.get("version"), str) and bool(re.fullmatch(r"v5\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?", row["version"]))


def execute(cfg, incident, response_id, revision, agent, indexer, manager, now=lambda: dt.datetime.now(dt.timezone.utc), emit=print):
    """The caller supplies authenticated fixed-origin transports. Never repeat external dispatch."""
    payload = request_body(cfg, incident, response_id, revision, agent)
    try:
        claim = receipt(indexer(payload), cfg, payload, now())
    except Exception:
        emit("Reservation unavailable or ambiguous. No manager request made. Inspect incident; do not retry blindly.")
        return 1
    outcome = "dispatch_unknown"
    try:
        # Confirm active agent identity and operator-pinned enrollment before the sole write.
        lookup = "/agents?" + urllib.parse.urlencode({"agents_list": agent, "select": "id,dateAdd,status,version", "limit": 1})
        if not preflight(manager("GET", lookup), cfg, agent):
            raise ValueError("Agent identity or eligibility unavailable")
        receipt(claim, cfg, payload, now())
        path = "/agents/scan/vulnerability?" + urllib.parse.urlencode({"agents_list": agent_id(agent)})
        if accepted(manager("PUT", path), agent):
            outcome = "manager_accepted"
    except Exception:
        pass
    try:
        report = request_body(cfg, incident, response_id, claim["revision"], agent, outcome)
        receipt(indexer(report), cfg, report)
    except Exception:
        emit("Dispatch outcome could not be recorded. Do not retry; stop runner and reconcile incident.")
        return 1
    emit("Manager acknowledgement recorded; endpoint execution unverified." if outcome == "manager_accepted"
         else "Ambiguous dispatch recorded; do not retry; independent reconciliation required.")
    return 0 if outcome == "manager_accepted" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--incident", required=True)
    parser.add_argument("--response", required=True)
    parser.add_argument("--revision", required=True, type=int)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--confirm-approved-scan", required=True, action="store_true")
    args = parser.parse_args()
    try:
        if args.config.stat().st_size > 16384:
            raise ValueError("Configuration too large")
        cfg = config(args.config.read_text(encoding="utf-8"))
        request_body(cfg, args.incident, args.response, args.revision, args.agent)
        indexer = client(cfg["indexer"], cfg["indexer_ca"])
        manager = client(cfg["manager"], cfg["manager_ca"])
        indexer_auth = basic(cfg["indexer_user"], os.environ.pop("WAZUH_SOAR_INDEXER_PASSWORD", ""))
        manager_auth = basic(cfg["manager_user"], os.environ.pop("WAZUH_SOAR_MANAGER_PASSWORD", ""))
        # Authenticate before reserving so an invalid credential cannot consume the request.
        token = manager_token(manager("POST", "/security/user/authenticate", manager_auth))
        return execute(cfg, args.incident, args.response, args.revision, args.agent,
                       lambda payload: indexer("POST", DISPATCH, indexer_auth, payload),
                       lambda method, path: manager(method, path, "Bearer " + token))
    except Exception:
        print("Configuration or authentication unavailable. No dispatch attempted by setup.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
