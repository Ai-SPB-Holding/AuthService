#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

cd "$AUTH_ROOT" || exit 1

# Do not `source .env`: unquoted values with spaces (e.g. VITE_APP_NAME=Auth Admin) break sh.
if [ -f .env ]; then
	# shellcheck disable=SC2046
	eval "$(python3 "$AUTH_ROOT/test/scripts/dotenv_whitelist_export.py" "$AUTH_ROOT/.env")"
fi

# Production-like audience: same as dashboard / AUTH__ADMIN_API_AUDIENCE (default auth-service).
ADMIN_AUD="${AUTH__ADMIN_API_AUDIENCE:-auth-service}"
TENANT="${ESCALATION_TENANT_ID:-a1111111-1111-1111-1111-111111111111}"
EMAIL="${ESCALATION_REGULAR_EMAIL:-security-escalation-probe@authservice.local}"
PASS="${ESCALATION_REGULAR_PASSWORD:-EscalationProbe2026!Secure}"

if [ "${SECURITY_ESCALATION_SKIP:-0}" = "1" ]; then
	echo "run-security-escalation: skipped (SECURITY_ESCALATION_SKIP=1)"
	exit 0
fi

echo "run-security-escalation: applying DB seed (idempotent)..."
$COMPOSE -f "$COMPOSE_FILE" exec -T postgres psql -U auth -d auth -v ON_ERROR_STOP=1 \
	<"$AUTH_ROOT/test/sql/security_escalation_seed.sql"

echo "run-security-escalation: probing API (admin audience=${ADMIN_AUD})..."
if [ -n "${ESCALATION_ADMIN_EMAIL:-}" ] && [ -n "${ESCALATION_ADMIN_PASSWORD:-}" ]; then
	python3 "$AUTH_ROOT/test/scripts/check-admin-privilege-escalation.py" \
		--base-url "${BACKEND_EXTERNAL_URL}" \
		--tenant-id "${TENANT}" \
		--email "${EMAIL}" \
		--password "${PASS}" \
		--admin-audience "${ADMIN_AUD}" \
		--admin-email "${ESCALATION_ADMIN_EMAIL}" \
		--admin-password "${ESCALATION_ADMIN_PASSWORD}"
else
	python3 "$AUTH_ROOT/test/scripts/check-admin-privilege-escalation.py" \
		--base-url "${BACKEND_EXTERNAL_URL}" \
		--tenant-id "${TENANT}" \
		--email "${EMAIL}" \
		--password "${PASS}" \
		--admin-audience "${ADMIN_AUD}"
fi

echo "run-security-escalation: OK"
