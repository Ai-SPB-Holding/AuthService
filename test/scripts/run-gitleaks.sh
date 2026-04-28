#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

echo "Running gitleaks (secrets)..."
set +e
docker run --rm \
	-v "$AUTH_ROOT:/repo:rw" \
	-v "$CONFIG_DIR/gitleaks.toml:/config/gitleaks.toml:ro" \
	zricethezav/gitleaks:latest \
	detect --source=/repo --config=/config/gitleaks.toml \
	--report-path=/repo/test/reports/gitleaks.json \
	--report-format json -v
code=$?
set -e

if [ "$code" -ne 0 ]; then
	echo "BLOCKED: gitleaks exit $code (see $REPORTS_DIR/gitleaks.json if generated)" >&2
	exit 1
fi
echo "OK: gitleaks passed."
