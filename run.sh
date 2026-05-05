#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$ROOT_DIR}"

BIN_DIR="$APP_DIR/bin"
FRONT_DIR="$APP_DIR/frontend"
CONF_DIR="$APP_DIR/config"
RUN_DIR="$APP_DIR/.run"

BACKEND_BIN="${BACKEND_BIN:-$BIN_DIR/auth_service}"
ENV_FILE="${ENV_FILE:-$APP_DIR/.env}"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-$APP_DIR/migrations}"

# Backend port defaults; may be overridden from .env (SERVER__PORT) in init_config_from_env
BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8080}"
BACKEND_ADDR="${BACKEND_ADDR:-$BACKEND_HOST:$BACKEND_PORT}"
BACKEND_HEALTH_URL="${BACKEND_HEALTH_URL:-http://$BACKEND_HOST:$BACKEND_PORT/health}"

DASHBOARD_LISTEN_PORT="${DASHBOARD_LISTEN_PORT:-5173}"
DASHBOARD_HEALTH_URL="${DASHBOARD_HEALTH_URL:-http://127.0.0.1:${DASHBOARD_LISTEN_PORT}/api/health}"

NGINX_BIN="${NGINX_BIN:-nginx}"
NGINX_CONF="${NGINX_CONF:-$CONF_DIR/nginx.conf}"

BACKEND_PID_FILE="$RUN_DIR/backend.pid"
NGINX_PID_FILE="$RUN_DIR/nginx.pid"

mkdir -p "$RUN_DIR"

log() { printf '%s\n' "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { log "ERROR: missing dependency: $1"; exit 1; }
}

is_pid_running() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

read_pid() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  tr -d ' \n\r\t' <"$f"
}

wait_http() {
  local url="$1"
  local seconds="${2:-60}"
  local deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    if command -v curl >/dev/null 2>&1; then
      if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -qO- "$url" >/dev/null 2>&1; then return 0; fi
    fi
    sleep 1
  done
  return 1
}

dotenv_get() {
  local key="$1"
  if [[ ! -f "$ENV_FILE" ]]; then
    return 1
  fi
  # Python parser avoids "source .env" pitfalls with quotes/spaces/\n escapes.
  python3 - "$ENV_FILE" "$key" <<'PY'
import os, re, sys
path, key = sys.argv[1], sys.argv[2]
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
        if k != key:
            continue
        v = unquote(v)
        sys.stdout.write(v)
        sys.exit(0)
sys.exit(1)
PY
}

export_env_vars() {
  if [[ ! -f "$ENV_FILE" ]]; then
    return 0
  fi
  # Export a safe subset of variables from .env into the current process environment.
  # This avoids relying on dotenv parsing inside the Rust app (which can fail on edge-case formatting).
  local exports
  exports="$(python3 - "$ENV_FILE" <<'PY'
import re, sys
path = sys.argv[1]
line_re = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$')
allowed_prefixes = (
    "SERVER__", "DATABASE__", "REDIS__", "AUTH__", "OIDC__", "CORS__", "METRICS__", "EMAIL__", "TOTP__", "VITE__",
    "DOMAIN", "API_DOMAIN",
)
def unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1]
    return v
def sh_single_quote(v: str) -> str:
    # Wrap in single-quotes and escape embedded single quotes safely for sh/bash.
    return "'" + v.replace("'", "'\"'\"'") + "'"
out = []
with open(path, "r", encoding="utf-8") as f:
    for raw in f:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = line_re.match(raw)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if not k.startswith(allowed_prefixes):
            continue
        v = unquote(v)
        out.append(f"export {k}={sh_single_quote(v)}")
print("\n".join(out))
PY
)"
  if [[ -n "${exports:-}" ]]; then
    # shellcheck disable=SC1090
    eval "$exports"
  fi
}

init_config_from_env() {
  export_env_vars
  if [[ -f "$ENV_FILE" ]]; then
    local p
    p="$(dotenv_get SERVER__PORT || true)"
    if [[ -n "${p:-}" ]]; then
      BACKEND_PORT="$p"
      BACKEND_ADDR="${BACKEND_HOST}:${BACKEND_PORT}"
      BACKEND_HEALTH_URL="http://${BACKEND_HOST}:${BACKEND_PORT}/health"
      DASHBOARD_HEALTH_URL="http://127.0.0.1:${DASHBOARD_LISTEN_PORT}/api/health"
    fi
  fi
}

validate_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    log "ERROR: .env not found at $ENV_FILE"
    log "Tip: run ./init-env.sh quick (or manual) first."
    exit 1
  fi

  local cookie totp priv pub issuer db redis
  cookie="$(dotenv_get AUTH__COOKIE_SECRET || true)"
  totp="$(dotenv_get TOTP__ENCRYPTION_KEY_B64 || true)"
  priv="$(dotenv_get AUTH__JWT_PRIVATE_KEY_PEM || true)"
  pub="$(dotenv_get AUTH__JWT_PUBLIC_KEY_PEM || true)"
  issuer="$(dotenv_get SERVER__ISSUER || true)"
  db="$(dotenv_get DATABASE__URL || true)"
  redis="$(dotenv_get REDIS__URL || true)"

  [[ -n "$db" ]] || { log "ERROR: DATABASE__URL is empty in $ENV_FILE"; exit 1; }
  [[ -n "$redis" ]] || { log "ERROR: REDIS__URL is empty in $ENV_FILE"; exit 1; }
  [[ -n "$issuer" ]] || { log "ERROR: SERVER__ISSUER is empty in $ENV_FILE"; exit 1; }

  if [[ -z "$cookie" || "$cookie" == REPLACE_WITH_* ]]; then
    log "ERROR: AUTH__COOKIE_SECRET is not set (or placeholder) in $ENV_FILE"
    exit 1
  fi
  if [[ -z "$totp" || "$totp" == REPLACE_WITH_* ]]; then
    log "ERROR: TOTP__ENCRYPTION_KEY_B64 is not set (or placeholder) in $ENV_FILE"
    exit 1
  fi
  if [[ -z "$priv" || "$priv" != *"BEGIN PRIVATE KEY"* ]]; then
    log "ERROR: AUTH__JWT_PRIVATE_KEY_PEM looks missing/invalid in $ENV_FILE"
    exit 1
  fi
  if [[ -z "$pub" || "$pub" != *"BEGIN PUBLIC KEY"* ]]; then
    log "ERROR: AUTH__JWT_PUBLIC_KEY_PEM looks missing/invalid in $ENV_FILE"
    exit 1
  fi
}

apply_migrations() {
  require_cmd psql
  local db_url
  db_url="$(dotenv_get DATABASE__URL || true)"
  [[ -n "$db_url" ]] || { log "ERROR: DATABASE__URL missing; cannot run migrations"; exit 1; }

  if [[ ! -d "$MIGRATIONS_DIR" ]]; then
    log "ERROR: migrations dir not found: $MIGRATIONS_DIR"
    exit 1
  fi

  log "migrations: applying from $MIGRATIONS_DIR"
  shopt -s nullglob
  local files=("$MIGRATIONS_DIR"/*.sql)
  if (( ${#files[@]} == 0 )); then
    log "ERROR: no migration files found in $MIGRATIONS_DIR"
    exit 1
  fi
  IFS=$'\n' files=($(printf '%s\n' "${files[@]}" | sort))
  unset IFS

  for f in "${files[@]}"; do
    log "migrations: $(basename "$f")"
    psql "$db_url" -v ON_ERROR_STOP=1 -f "$f" >/dev/null
  done
  log "migrations: done"
}

start_backend() {
  if [[ ! -x "$BACKEND_BIN" ]]; then
    log "ERROR: backend binary not found/executable: $BACKEND_BIN"
    exit 1
  fi

if [[ -f "$BACKEND_PID_FILE" ]]; then
    local pid
    pid="$(read_pid "$BACKEND_PID_FILE" || true)"
    if [[ -n "${pid:-}" ]] && is_pid_running "$pid"; then
      log "backend: already running (pid $pid)"
      return 0
    fi
  fi

  log "backend: starting ($BACKEND_BIN) on $BACKEND_ADDR"
  (cd "$APP_DIR" && "$BACKEND_BIN") >/dev/null 2>"$RUN_DIR/backend.err" &
  echo "$!" >"$BACKEND_PID_FILE"

  if wait_http "$BACKEND_HEALTH_URL" 60; then
    log "backend: healthy ($BACKEND_HEALTH_URL)"
  else
    log "WARN: backend health check did not become ready in time: $BACKEND_HEALTH_URL"
    if [[ -s "$RUN_DIR/backend.err" ]]; then
      log "backend: last stderr:"
      tail -n 50 "$RUN_DIR/backend.err" 2>/dev/null || true
    fi
  fi
}

start_nginx() {
  if [[ ! -d "$FRONT_DIR" ]]; then
    log "ERROR: frontend folder not found: $FRONT_DIR"
    exit 1
  fi
  if [[ ! -f "$NGINX_CONF" ]]; then
    log "ERROR: nginx config not found: $NGINX_CONF"
    exit 1
  fi
  if ! command -v "$NGINX_BIN" >/dev/null 2>&1; then
    log "ERROR: nginx not found (set NGINX_BIN or install nginx)"
    exit 1
  fi

  if [[ -f "$NGINX_PID_FILE" ]]; then
    local pid
    pid="$(read_pid "$NGINX_PID_FILE" || true)"
    if [[ -n "${pid:-}" ]] && is_pid_running "$pid"; then
      log "nginx: already running (pid $pid)"
      return 0
    fi
  fi

  # nginx.conf in the package is a conf.d-style server block (from docker image).
  # For host nginx we need a full config with `http {}`.
  local server_snippet="$RUN_DIR/nginx.server.conf"
  local rendered="$RUN_DIR/nginx.runtime.conf"

  sed \
    -e "s/listen 80;/listen ${DASHBOARD_LISTEN_PORT};/g" \
    -e "s#root /usr/share/nginx/html;#root ${FRONT_DIR};#g" \
    -e "s#proxy_pass http://backend:8080/#proxy_pass http://${BACKEND_HOST}:${BACKEND_PORT}/#g" \
    -e "s#proxy_pass http://backend:8080/events#proxy_pass http://${BACKEND_HOST}:${BACKEND_PORT}/events#g" \
    "$NGINX_CONF" >"$server_snippet"

  cat >"$rendered" <<EOF
worker_processes auto;
pid $NGINX_PID_FILE;

events { worker_connections 1024; }

http {
  default_type  application/octet-stream;
  sendfile      on;
  tcp_nopush    on;
  tcp_nodelay   on;
  keepalive_timeout  65;

  # logs
  access_log $RUN_DIR/nginx.access.log;
  error_log  $RUN_DIR/nginx.error.log warn;

  include $server_snippet;
}
EOF

  log "nginx: starting (listen :$DASHBOARD_LISTEN_PORT)"
  if ! "$NGINX_BIN" -c "$rendered" -g "daemon on;" >/dev/null 2>"$RUN_DIR/nginx.start.err"; then
    log "ERROR: failed to start nginx"
    # Run config test to surface the real reason.
    "$NGINX_BIN" -t -c "$rendered" >/dev/null 2>"$RUN_DIR/nginx.test.err" || true
    if [[ -s "$RUN_DIR/nginx.test.err" ]]; then
      log "nginx: config test output:"
      cat "$RUN_DIR/nginx.test.err" 2>/dev/null || true
    elif [[ -s "$RUN_DIR/nginx.start.err" ]]; then
      log "nginx: start stderr:"
      cat "$RUN_DIR/nginx.start.err" 2>/dev/null || true
    elif [[ -f "$RUN_DIR/nginx.error.log" ]]; then
      log "nginx: last error log:"
      tail -n 50 "$RUN_DIR/nginx.error.log" 2>/dev/null || true
    fi
    exit 1
  fi

  if wait_http "$DASHBOARD_HEALTH_URL" 60; then
    log "dashboard: ready ($DASHBOARD_HEALTH_URL)"
  else
    log "WARN: dashboard health check did not become ready in time: $DASHBOARD_HEALTH_URL"
  fi
}

stop_backend() {
  local pid
  pid="$(read_pid "$BACKEND_PID_FILE" || true)"
  if [[ -z "${pid:-}" ]]; then
    log "backend: not running"
    return 0
  fi
  if is_pid_running "$pid"; then
    log "backend: stopping (pid $pid)"
    kill "$pid" 2>/dev/null || true
    for _ in {1..30}; do
      is_pid_running "$pid" || break
      sleep 1
    done
    is_pid_running "$pid" && kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$BACKEND_PID_FILE"
}

stop_nginx() {
  local pid
  pid="$(read_pid "$NGINX_PID_FILE" || true)"
  if [[ -z "${pid:-}" ]]; then
    log "nginx: not running"
    return 0
  fi
  if is_pid_running "$pid"; then
    log "nginx: stopping (pid $pid)"
    "$NGINX_BIN" -s quit -c "$RUN_DIR/nginx.runtime.conf" >/dev/null 2>&1 || kill "$pid" 2>/dev/null || true
    for _ in {1..30}; do
      is_pid_running "$pid" || break
      sleep 1
    done
    is_pid_running "$pid" && kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$NGINX_PID_FILE"
}

cmd_init() {
  require_cmd python3
  init_config_from_env
  validate_env
  apply_migrations
  if [[ -x "$APP_DIR/scripts/server-check.sh" ]]; then
    log "server-check: running"
    (cd "$APP_DIR" && ./scripts/server-check.sh) || {
      log "WARN: server-check failed"
    }
  else
    log "WARN: scripts/server-check.sh not found/executable; skipping"
  fi
  log "init: done"
}

cmd_start() {
  init_config_from_env
  start_backend
}

cmd_stop() {
  stop_nginx
  stop_backend
}

cmd_status() {
  local ok=0
  local pid

  pid="$(read_pid "$BACKEND_PID_FILE" || true)"
  if [[ -n "${pid:-}" ]] && is_pid_running "$pid"; then
    log "backend: running (pid $pid)"
  else
    log "backend: stopped"
    ok=1
  fi

  pid="$(read_pid "$NGINX_PID_FILE" || true)"
  if [[ -n "${pid:-}" ]] && is_pid_running "$pid"; then
    log "nginx: running (pid $pid) listen :$DASHBOARD_LISTEN_PORT"
  else
    log "nginx: stopped"
    ok=1
  fi

  return "$ok"
}

cmd_restart() {
  cmd_stop
  cmd_start
}

usage() {
  cat <<EOF
Usage: ./run.sh <command>

Commands:
  init       Validate .env + apply DB migrations + run server checks
  start      Start backend + dashboard (nginx)
  stop       Stop backend + dashboard
  restart    Restart both
  status     Show status (exit 0 if all running)

Environment (optional):
  BACKEND_BIN=...                 Path to auth_service binary
  BACKEND_HEALTH_URL=...          Default: $BACKEND_HEALTH_URL
  DASHBOARD_LISTEN_PORT=...       Default: $DASHBOARD_LISTEN_PORT
  NGINX_BIN=nginx                 Nginx binary name/path
EOF
}

case "${1:-}" in
  init) cmd_init ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  ""|-h|--help|help) usage ;;
  *) log "ERROR: unknown command: $1"; usage; exit 2 ;;
esac

