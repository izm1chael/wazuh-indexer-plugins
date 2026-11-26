#!/usr/bin/env sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT HUP INT TERM
javac --release 17 -Xlint:all -Werror -d "$out" "$here"/src/com/wazuh/wade/*.java "$here"/test/com/wazuh/wade/*.java
java -cp "$out" com.wazuh.wade.DetectionKernelTests
java -cp "$out" com.wazuh.wade.AnalyticsTests
