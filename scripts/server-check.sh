#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"
BACKEND_URL="${BACKEND_URL:-}"
DASHBOARD_PORT="${DASHBOARD_PORT:-5173}"
DASHBOARD_URL="${DASHBOARD_URL:-http://127.0.0.1:${DASHBOARD_PORT}}"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }

command -v curl >/dev/null 2>&1 || fail "curl is required"

if [[ -f "$ROOT_DIR/.env" ]]; then
  ok ".env exists"
else
  ok ".env not found (this may be fine if env vars are provided via systemd)"
fi

if [[ -z "${BACKEND_URL}" && -f "$ENV_FILE" ]]; then
  # Read SERVER__PORT from .env without sourcing.
  port="$(python3 - "$ENV_FILE" <<'PY'
import re, sys
path = sys.argv[1]
line_re = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$')
def unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1]
    return v
with open(path, "r", encoding="utf-8") as f:
    for raw in f:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = line_re.match(raw)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if k == "SERVER__PORT":
            sys.stdout.write(unquote(v))
            sys.exit(0)
sys.exit(1)
PY
)" || true
  if [[ -n "${port:-}" ]]; then
    BACKEND_URL="http://127.0.0.1:${port}"
  fi
fi

BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:8080}"

curl -fsS "$BACKEND_URL/health" >/dev/null || fail "backend not healthy at $BACKEND_URL/health"
ok "backend /health reachable"

curl -fsS "$BACKEND_URL/.well-known/openid-configuration" >/dev/null || fail "OIDC discovery not reachable at $BACKEND_URL/.well-known/openid-configuration"
ok "backend OIDC discovery reachable"

curl -fsS "$DASHBOARD_URL/" >/dev/null || fail "dashboard not reachable at $DASHBOARD_URL/"
ok "dashboard reachable"

curl -fsS "$DASHBOARD_URL/api/health" >/dev/null || fail "dashboard /api/health not reachable at $DASHBOARD_URL/api/health"
ok "dashboard /api/health reachable (proxy to backend)"

echo "server-check: all checks passed."

