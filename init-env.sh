#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="${TEMPLATE_FILE:-$ROOT_DIR/.env.example}"
OUT_FILE="${OUT_FILE:-$ROOT_DIR/.env}"

mode="${1:-}"
if [[ -z "$mode" ]]; then
  echo "Choose mode:"
  echo "  1) quick  (secure defaults + generate secrets/keys)"
  echo "  2) manual (prompt for everything important)"
  read -r -p "> " choice
  case "$choice" in
    1|quick) mode="quick" ;;
    2|manual) mode="manual" ;;
    *) echo "Invalid choice"; exit 2 ;;
  esac
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing dependency: $1" >&2; exit 1; }
}

ask() {
  local prompt="$1"
  local def="${2:-}"
  local out
  if [[ -n "$def" ]]; then
    read -r -p "$prompt [$def]: " out
    echo "${out:-$def}"
  else
    read -r -p "$prompt: " out
    echo "$out"
  fi
}

ask_yes_no() {
  local prompt="$1"
  local def="${2:-n}"
  local out
  read -r -p "$prompt (y/n) [$def]: " out
  out="${out:-$def}"
  case "$out" in
    y|Y|yes|YES) echo "true" ;;
    n|N|no|NO) echo "false" ;;
    *) echo "false" ;;
  esac
}

gen_hex() {
  require_cmd openssl
  local bytes="${1:-32}"
  openssl rand -hex "$bytes"
}

gen_b64() {
  require_cmd openssl
  local bytes="${1:-32}"
  # base64 without trailing newline
  openssl rand -base64 "$bytes" | tr -d '\n'
}

pem_to_one_line() {
  # Convert PEM into one line with literal \n escapes (config-friendly).
  # Input: file path
  local f="$1"
  awk 'BEGIN{ORS=""}{gsub(/\r/,""); printf "%s\\n",$0} END{}' "$f"
}

gen_rsa_pems_one_line() {
  require_cmd openssl
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  # 3072 is a good baseline (balance security/perf).
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$tmpdir/private.pem" >/dev/null 2>&1
  openssl pkey -in "$tmpdir/private.pem" -pubout -out "$tmpdir/public.pem" >/dev/null 2>&1

  local priv pub
  priv="$(pem_to_one_line "$tmpdir/private.pem")"
  pub="$(pem_to_one_line "$tmpdir/public.pem")"

  printf '%s\n%s\n' "$priv" "$pub"
}

if [[ ! -f "$TEMPLATE_FILE" ]]; then
  echo "ERROR: template not found: $TEMPLATE_FILE" >&2
  exit 1
fi

if [[ -f "$OUT_FILE" ]]; then
  overwrite="$(ask_yes_no "File $OUT_FILE exists. Overwrite?" "n")"
  if [[ "$overwrite" != "true" ]]; then
    echo "Aborted."
    exit 0
  fi
fi

echo "Writing $OUT_FILE from template $TEMPLATE_FILE"
echo

# Common prompts
issuer="$(ask "SERVER__ISSUER (public base URL of this service, used in tokens/metadata)" "http://localhost:8080")"
cors_allowed="$(ask "CORS__ALLOWED_ORIGINS (comma-separated, empty = deny cross-origin)" "")"
db_url="$(ask "DATABASE__URL" "postgres://auth:auth@localhost:5432/auth")"
redis_url="$(ask "REDIS__URL" "redis://127.0.0.1:6379")"

admin_aud="$(ask "AUTH__ADMIN_API_AUDIENCE (must match dashboard VITE_DEFAULT_AUDIENCE)" "auth-service")"
vite_api_base="$(ask "VITE_API_BASE_URL (dashboard -> API base)" "http://localhost:8080")"
vite_sse="$(ask "VITE_SSE_URL (dashboard -> SSE URL)" "http://localhost:8080/events")"
vite_app_name="$(ask "VITE_APP_NAME" "Auth Admin")"
vite_env_name="$(ask "VITE_ENV_NAME" "production")"

if [[ "$mode" == "quick" ]]; then
  echo "Quick mode: generating strong secrets/keys and setting secure defaults."
  echo

  cookie_secret="$(gen_hex 32)" # 64 hex chars
  totp_key_b64="$(gen_b64 32)"  # 32 bytes -> base64
  metrics_token="$(gen_hex 32)"
  bootstrap_token="$(gen_hex 32)"

  readarray -t pems < <(gen_rsa_pems_one_line)
  jwt_priv="${pems[0]}"
  jwt_pub="${pems[1]}"

  require_login_2fa="true"
  vite_set_idp_session="true"
  global_admin_ids="" # safer default: opt-in after deployment

  # Leave OIDC proxy empty by default; do not mask misconfigurations.
  oidc_server_metadata_url=""
  oidc_login_url=""

  # Secrets: ask optionally (can be unused)
  email_api_key_secret="$(ask "EMAIL__API_KEY_SECRET (optional; leave empty if not using email sender)" "")"

elif [[ "$mode" == "manual" ]]; then
  echo "Manual mode: you'll be prompted for secrets and security toggles."
  echo

  echo "JWT keys (RSA PEM, one-line with \\n escapes)."
  echo "Tip: you can press Enter to auto-generate."
  jwt_priv_in="$(ask "AUTH__JWT_PRIVATE_KEY_PEM" "")"
  jwt_pub_in="$(ask "AUTH__JWT_PUBLIC_KEY_PEM" "")"
  if [[ -z "$jwt_priv_in" || -z "$jwt_pub_in" ]]; then
    readarray -t pems < <(gen_rsa_pems_one_line)
    jwt_priv="${jwt_priv_in:-${pems[0]}}"
    jwt_pub="${jwt_pub_in:-${pems[1]}}"
  else
    jwt_priv="$jwt_priv_in"
    jwt_pub="$jwt_pub_in"
  fi

  cookie_secret="$(ask "AUTH__COOKIE_SECRET (>=32 bytes; Enter to auto-generate)" "")"
  if [[ -z "$cookie_secret" ]]; then cookie_secret="$(gen_hex 32)"; fi

  totp_key_b64="$(ask "TOTP__ENCRYPTION_KEY_B64 (openssl rand -base64 32; Enter to auto-generate)" "")"
  if [[ -z "$totp_key_b64" ]]; then totp_key_b64="$(gen_b64 32)"; fi

  require_login_2fa="$(ask_yes_no "AUTH__REQUIRE_LOGIN_2FA (require TOTP for every user)" "y")"
  vite_set_idp_session="$(ask_yes_no "VITE_SET_IDP_SESSION (dashboard sets idp_session cookie for /authorize)" "y")"

  global_admin_ids="$(ask "AUTH__GLOBAL_ADMIN_USER_IDS (comma-separated UUIDs; empty is safer)" "")"

  oidc_server_metadata_url="$(ask "OIDC__SERVER_METADATA_URL (optional; proxy discovery from upstream)" "")"
  oidc_login_url="$(ask "OIDC__LOGIN_URL (optional; redirect for unauthenticated browser /authorize)" "")"

  metrics_token="$(ask "METRICS__BYPASS_TOKEN (optional; Enter to auto-generate for safety)" "")"
  if [[ -z "$metrics_token" ]]; then metrics_token="$(gen_hex 32)"; fi

  email_api_key_secret="$(ask "EMAIL__API_KEY_SECRET (optional)" "")"
else
  echo "Unknown mode: $mode" >&2
  exit 2
fi

# Build final .env (do not edit .env.example in-place; keep it as template)
cat >"$OUT_FILE" <<EOF
SERVER__HOST=0.0.0.0
SERVER__PORT=8080
SERVER__ISSUER=$issuer
CORS__ALLOWED_ORIGINS=$cors_allowed

DATABASE__URL=$db_url
DATABASE__POOL_SIZE=20

REDIS__URL=$redis_url
REDIS__PREFIX=auth

AUTH__JWT_PRIVATE_KEY_PEM=$jwt_priv
AUTH__JWT_PUBLIC_KEY_PEM=$jwt_pub
AUTH__ACCESS_TTL_SECONDS=900
AUTH__REFRESH_TTL_SECONDS=1209600
AUTH__COOKIE_SECRET=$cookie_secret
AUTH__ADMIN_API_AUDIENCE=$admin_aud
AUTH__REQUIRE_LOGIN_2FA=$require_login_2fa
AUTH__GLOBAL_ADMIN_USER_IDS=$global_admin_ids
AUTH__ENV_FILE_PATH=.env

OIDC__KEYCLOAK_CLIENT_ID=auth-service
OIDC__KEYCLOAK_CLIENT_SECRET=replace_me
OIDC__CLIENT_MFA_ENFORCE=true
OIDC__REDIRECT_URL=$issuer/callback
OIDC__LOGIN_URL=$oidc_login_url
OIDC__SERVER_METADATA_URL=$oidc_server_metadata_url

METRICS__BYPASS_TOKEN=$metrics_token
AUTH__BOOTSTRAP_ADMIN_TOKEN=$bootstrap_token

EMAIL__API_KEY_SECRET=$email_api_key_secret

TOTP__ENCRYPTION_KEY_B64=$totp_key_b64

VITE_APP_NAME="$vite_app_name"
VITE_API_BASE_URL=$vite_api_base
VITE_SSE_URL=$vite_sse
VITE_DEFAULT_AUDIENCE=$admin_aud
VITE_ENV_NAME=$vite_env_name
VITE_SET_IDP_SESSION=$vite_set_idp_session
EOF

chmod 600 "$OUT_FILE" || true

echo
echo "Done."
echo "Next:"
echo "  - review $OUT_FILE"
echo "  - start stack (docker) or run release ./run.sh start"

