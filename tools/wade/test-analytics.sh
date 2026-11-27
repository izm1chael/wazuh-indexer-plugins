#!/usr/bin/env sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT HUP INT TERM
javac --release 17 -Xlint:all -Werror -d "$out" "$here"/src/com/wazuh/wade/*.java "$here"/test/com/wazuh/wade/*.java
for suite in DetectionKernelTests AnalyticsTests ControlTests GovernanceTests PipelineTests FeatureHistoryTests CrossWindowCorrelationTests FindingReconciliationTests WindowServiceTests IndexWindowStoreTests; do
    java -cp "$out" "com.wazuh.wade.$suite"
done
