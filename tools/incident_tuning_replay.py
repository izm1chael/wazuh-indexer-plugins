#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator-only paired detection replay against pre-provisioned disposable RC2 test integrations."""
import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PATH = "/_plugins/_content_manager/logtest/detection"
TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
MAX_INPUT = 16 * 1024 * 1024
MAX_EVENT = 64 * 1024
MAX_RESPONSE = 1024 * 1024
MAX_ROWS = 1000


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError("Unexpected or missing fixture fields")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def strict_json(raw):
    def bad_constant(_):
        raise ValueError("Non-finite JSON value")
    return json.loads(raw, object_pairs_hook=no_duplicates, parse_constant=bad_constant)


def read_bounded(path, limit):
    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Input exceeds size limit")
    return data


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def validate_fixture(value):
    exact(value, ("split", "controls", "rows"))
    if value["split"] != "holdout":
        raise ValueError("Declare an independent holdout split")
    controls, rows = value["controls"], value["rows"]
    if not isinstance(controls, list) or not 2 <= len(controls) <= 20:
        raise ValueError("Two to twenty controls required")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ROWS:
        raise ValueError("One to 1000 holdout rows required")
    seen = set()
    for row in controls + rows:
        exact(row, ("id", "label", "input"))
        if (not isinstance(row["id"], str) or TOKEN.fullmatch(row["id"]) is None
                or row["id"] in seen or row["label"] not in ("malicious", "benign", "unknown")
                or not isinstance(row["input"], dict) or not row["input"]
                or len(canonical(row["input"])) > MAX_EVENT):
            raise ValueError("Invalid or duplicate normalized event")
        seen.add(row["id"])
    if {row["label"] for row in controls} != {"malicious", "benign"}:
        raise ValueError("Both positive and negative controls required")
    return controls, rows


def endpoint(base):
    parsed = urllib.parse.urlsplit(base)
    if (parsed.scheme != "https" or parsed.hostname not in ("127.0.0.1", "::1")
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or parsed.port is None or not 1 <= parsed.port <= 65535):
        raise ValueError("Explicit HTTPS loopback address and port required")
    return base.rstrip("/") + PATH


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise urllib.error.HTTPError(args[0].full_url, 403, "Redirect forbidden", {}, None)


def detection_result(value):
    """A 200/zero-rule response is NOT a negative result: require exactly one evaluated rule."""
    if not isinstance(value, dict) or type(value.get("status")) is not int or value["status"] != 200:
        raise ValueError("Invalid detection response envelope")
    result = value.get("message")
    if (not isinstance(result, dict) or result.get("status") != "success"
            or type(result.get("rules_evaluated")) is not int or result["rules_evaluated"] != 1
            or type(result.get("rules_matched")) is not int or result["rules_matched"] not in (0, 1)
            or not isinstance(result.get("matches"), list)
            or len(result["matches"]) != result["rules_matched"]
            or result.get("error") is not None or result.get("errors") not in (None, [])):
        raise ValueError("Incomplete, failed or ambiguous detection evaluation")
    return result["rules_matched"] == 1


def make_call(url, integration, space, ca_file, username, password):
    if UUID.fullmatch(integration) is None or space != "test":
        raise ValueError("Pre-provisioned test integration UUID required")
    uri = endpoint(url)
    if not username or not password or ":" in username:
        raise ValueError("Separate disposable tester credentials required")
    auth = base64.b64encode((username + ":" + password).encode("utf-8")).decode("ascii")
    context = ssl.create_default_context(cafile=ca_file)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context), NoRedirect())

    def call(event):
        data = canonical({"space": space, "integration": integration, "input": event})
        req = urllib.request.Request(uri, data=data, method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": "Basic " + auth})
        try:
            with opener.open(req, timeout=15) as response:
                if response.status != 200:
                    raise ValueError("Unexpected HTTP status")
                body = response.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise ValueError("Response exceeds size limit")
            return detection_result(strict_json(body))
        except (OSError, ValueError, urllib.error.URLError):
            # Do not print raw events, responses, URLs, credentials or error bodies.
            raise ValueError("Detection test failed; no complete replay produced") from None
    return call


def paired_digest(rows):
    h = hashlib.sha256(b"wazuh-tuning-fixture-v1\n")
    for row in sorted(rows, key=lambda row: row["id"]):
        h.update(("%s\t%s\t%d\t%d\n" % (row["id"], row["label"], row["baseline"], row["candidate"])).encode("ascii"))
    return h.hexdigest()


def run_replay(fixture, baseline_call, candidate_call, baseline_hash, candidate_hash):
    controls, rows = validate_fixture(fixture)
    if (re.fullmatch(r"[a-f0-9]{64}", baseline_hash) is None
            or re.fullmatch(r"[a-f0-9]{64}", candidate_hash) is None or baseline_hash == candidate_hash):
        raise ValueError("Distinct rule asset SHA-256 values required")

    def verify_controls():
        for row in controls:
            expected = row["label"] == "malicious"
            if baseline_call(row["input"]) is not expected or candidate_call(row["input"]) is not expected:
                raise ValueError("Positive or negative control failed; no complete replay produced")

    verify_controls()
    result = []
    for row in rows:
        baseline = baseline_call(row["input"])
        candidate = candidate_call(row["input"])
        if type(baseline) is not bool or type(candidate) is not bool:
            raise ValueError("Missing paired outcome")
        result.append({"id": row["id"], "label": row["label"], "baseline": baseline, "candidate": candidate})
    verify_controls()
    return {"fixture": {"baseline_version": baseline_hash, "candidate_version": candidate_hash,
                        "split": "holdout", "rows": result},
            "receipt": {"mode": "disposable_detection_only_logtest",
                        "version_provenance": "operator_supplied_asset_files_not_verified_loaded",
                        "input_sha256": hashlib.sha256(canonical(fixture)).hexdigest(),
                        "fixture_sha256": paired_digest(result),
                        "positive_negative_controls": "passed_before_and_after",
                        "control_count": len(controls), "paired_count": len(result),
                        "completed_at": datetime.now(timezone.utc).isoformat()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-disposable", action="store_true",
                        help="Confirm both target integrations are isolated and contain one enabled test rule")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--output", required=True, help="New output path; never overwrite")
    for side in ("baseline", "candidate"):
        parser.add_argument("--" + side + "-url", required=True)
        parser.add_argument("--" + side + "-integration", required=True)
        parser.add_argument("--" + side + "-ca", required=True)
        parser.add_argument("--" + side + "-rule", required=True)
    args = parser.parse_args()
    if not args.confirm_disposable:
        parser.error("Explicit disposable environment confirmation required")
    try:
        if Path(args.output).exists():
            raise ValueError("Output already exists")
        if (endpoint(args.baseline_url), args.baseline_integration) == (endpoint(args.candidate_url), args.candidate_integration):
            raise ValueError("Distinct test targets required")
        fixture = strict_json(read_bounded(args.fixture, MAX_INPUT))
        validate_fixture(fixture)
        hashes = [hashlib.sha256(read_bounded(getattr(args, side + "_rule"), MAX_EVENT)).hexdigest()
                  for side in ("baseline", "candidate")]
        calls = [make_call(getattr(args, side + "_url"), getattr(args, side + "_integration"), "test",
                           getattr(args, side + "_ca"), os.environ.get("WAZUH_REPLAY_" + side.upper() + "_USER", ""),
                           os.environ.get("WAZUH_REPLAY_" + side.upper() + "_PASSWORD", ""))
                 for side in ("baseline", "candidate")]
        result = run_replay(fixture, *calls, *hashes)
        result["receipt"]["baseline_integration"] = args.baseline_integration
        result["receipt"]["candidate_integration"] = args.candidate_integration
        # Exclusive creation, restricted local mode; no output is created before successful completion.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(result, out, indent=2, allow_nan=False)
            out.write("\n")
        print("Completed paired replay. Inspect receipt and extract fixture for tuning evaluation.")
    except Exception:
        print("Replay failed; verify local setup, controls and fixture. No qualified replay claimed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
