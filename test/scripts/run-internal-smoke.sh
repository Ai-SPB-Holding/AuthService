#!/usr/bin/env sh
# Smoke from inside backend container (same network as DB/Redis).
set -e
. "$(dirname "$0")/common.sh"

echo "Internal: GET http://127.0.0.1:8080/health from backend container..."
$COMPOSE -f "$COMPOSE_FILE" exec -T backend /bin/sh -c \
	'wget -qO- http://127.0.0.1:8080/health' | head -c 500
echo ""
echo "Internal smoke OK."
