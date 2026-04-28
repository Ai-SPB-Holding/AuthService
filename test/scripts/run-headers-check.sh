#!/usr/bin/env sh
# External header checks (dashboard nginx + backend).
set -e
. "$(dirname "$0")/common.sh"

fail=0

check_header() {
	name="$1"
	url="$2"
	hdr="$3"
	if ! curl -fsSI --max-time 10 "$url" | tr -d '\r' | grep -qi "^${hdr}:"; then
		echo "FAIL: $name missing header $hdr ($url)" >&2
		fail=1
	else
		echo "OK: $name has $hdr"
	fi
}

echo "--- Dashboard ($DASHBOARD_EXTERNAL_URL/) ---"
check_header dashboard "$DASHBOARD_EXTERNAL_URL/" "X-Content-Type-Options"
check_header dashboard "$DASHBOARD_EXTERNAL_URL/" "X-Frame-Options"
check_header dashboard "$DASHBOARD_EXTERNAL_URL/" "Referrer-Policy"
check_header dashboard "$DASHBOARD_EXTERNAL_URL/" "Content-Security-Policy"

echo "--- Backend ($BACKEND_EXTERNAL_URL/health) ---"
check_header backend_health "$BACKEND_EXTERNAL_URL/health" "X-Content-Type-Options"
check_header backend_health "$BACKEND_EXTERNAL_URL/health" "Cross-Origin-Resource-Policy"
if ! curl -fsS --max-time 10 "$BACKEND_EXTERNAL_URL/health" >/dev/null; then
	echo "FAIL: backend /health" >&2
	fail=1
else
	echo "OK: backend /health body reachable"
fi

echo "--- Backend OIDC ($BACKEND_EXTERNAL_URL/.well-known/openid-configuration) ---"
oidc_sc="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "$BACKEND_EXTERNAL_URL/.well-known/openid-configuration" || echo "000")"
if [ "$oidc_sc" != "200" ]; then
	echo "FAIL: openid-configuration HTTP $oidc_sc (expected 200; empty OIDC__SERVER_METADATA_URL in .env for embedded IdP)" >&2
	fail=1
else
	echo "OK: openid-configuration returns 200"
	check_header backend_oidc "$BACKEND_EXTERNAL_URL/.well-known/openid-configuration" "X-Content-Type-Options"
	check_header backend_oidc "$BACKEND_EXTERNAL_URL/.well-known/openid-configuration" "Cache-Control"
fi

# HSTS is expected at TLS edge only; local HTTP may omit it — warn if absent (informational).
if curl -fsSI --max-time 10 "$DASHBOARD_EXTERNAL_URL/" | tr -d '\r' | grep -qi '^Strict-Transport-Security:'; then
	echo "OK: dashboard sends HSTS (unusual on plain HTTP)"
else
	echo "INFO: no HSTS on dashboard (expected for local http; set at reverse proxy in prod)"
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "Headers check passed."
