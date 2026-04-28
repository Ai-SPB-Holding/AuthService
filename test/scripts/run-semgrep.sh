#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

echo "Running Semgrep..."
set +e
docker run --rm \
	-v "$AUTH_ROOT:/src:rw" \
	-w /src \
	returntocorp/semgrep:latest \
	semgrep scan --metrics=off \
	--config p/security-audit \
	--config p/secrets \
	--json-output=/src/test/reports/semgrep.json
set -e

python3 "$SCRIPT_DIR/semgrep_gate.py" "$REPORTS_DIR/semgrep.json"
