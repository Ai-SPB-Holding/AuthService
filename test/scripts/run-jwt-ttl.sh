#!/usr/bin/env sh
# Bring up Docker Compose with JWT TTL overrides, migrate, seed probe user, run check-jwt-ttl.py.
set -e
. "$(dirname "$0")/common.sh"
cd "$AUTH_ROOT" || exit 1

if [ -f .env ]; then
	# shellcheck disable=SC2046
	eval "$(python3 "$AUTH_ROOT/test/scripts/dotenv_whitelist_export.py" "$AUTH_ROOT/.env")"
fi

OVERRIDE="$AUTH_ROOT/test/docker/jwt-ttl.override.yml"

echo "Starting stack (docker compose + jwt-ttl override)..."
$COMPOSE -f "$COMPOSE_FILE" -f "$OVERRIDE" up -d --build

echo "Applying migrations..."
for f in "$AUTH_ROOT"/backend/migrations/*.sql; do
	[ -f "$f" ] || continue
	echo "Applying $f..."
	$COMPOSE -f "$COMPOSE_FILE" -f "$OVERRIDE" exec -T postgres psql -U auth -d auth <"$f"
done

echo "Waiting for backend health..."
sh "$AUTH_ROOT/test/scripts/wait-for-http.sh" "${BACKEND_EXTERNAL_URL:-http://127.0.0.1:8080}/health" 180

echo "Applying JWT TTL test seed (idempotent)..."
$COMPOSE -f "$COMPOSE_FILE" -f "$OVERRIDE" exec -T postgres psql -U auth -d auth -v ON_ERROR_STOP=1 \
	<"$AUTH_ROOT/test/sql/security_escalation_seed.sql"

echo "Running JWT TTL HTTP checks (uses API expires_in and JWT exp; may take several minutes)..."
python3 "$AUTH_ROOT/test/scripts/check-jwt-ttl.py" \
	--base-url "${BACKEND_EXTERNAL_URL:-http://127.0.0.1:8080}" \
	--admin-audience "${AUTH__ADMIN_API_AUDIENCE:-auth-service}"

echo "run-jwt-ttl: OK"
