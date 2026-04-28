#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

echo "Running npm audit (package-lock only) for dashboard-ui..."
docker run --rm \
	-v "$AUTH_ROOT/dashboard-ui:/app:ro" \
	-w /app \
	node:22-alpine \
	sh -c 'npm audit --package-lock-only --json' \
	>"$REPORTS_DIR/npm-audit.json" || true

python3 "$SCRIPT_DIR/npm_audit_gate.py" "$REPORTS_DIR/npm-audit.json"
