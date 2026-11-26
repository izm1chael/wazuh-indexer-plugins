#!/usr/bin/env bash
# Offline deterministic comparison; does not contact an indexer.
set -euo pipefail
if [[ $# != 1 ]]; then echo "Usage: bash tools/qualify_incident_tuning_parity.sh DASHBOARD_CHECKOUT" >&2; exit 2; fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dashboard="$(cd "$1" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp "$root/plugins/setup/src/main/java/com/wazuh/setup/incident/TuningReplay.java" "$tmp/"
cp "$root/tests/qualification/ReplayHarness.java" "$root/tests/qualification/parity.cjs" "$tmp/"
cp "$dashboard/plugins/main/common/incidents/tuning-evaluation.ts" "$tmp/"
cd "$tmp"
mkdir java-out ts-out
javac --release 17 -d java-out TuningReplay.java ReplayHarness.java
tsc --strict --target es2020 --module commonjs --outDir ts-out tuning-evaluation.ts
node parity.cjs
