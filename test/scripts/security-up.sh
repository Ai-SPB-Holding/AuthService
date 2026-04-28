#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

echo "Starting stack (docker compose)..."
make -f "$AUTH_ROOT/Makefile.docker" up

echo "Applying migrations..."
make -f "$AUTH_ROOT/Makefile.docker" migrate || {
	echo "WARN: migrate failed (DB may still be initializing); continuing wait" >&2
}

sh "$SCRIPT_DIR/wait-for-http.sh" "$BACKEND_EXTERNAL_URL/health" 180
sh "$SCRIPT_DIR/wait-for-http.sh" "$DASHBOARD_EXTERNAL_URL/api/health" 120

echo "security-up: ready."
