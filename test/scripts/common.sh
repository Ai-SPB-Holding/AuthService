#!/usr/bin/env sh
# Shared env for security harness. Source from other scripts: . "$(dirname "$0")/common.sh"

set -e

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
AUTH_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
export AUTH_ROOT

export COMPOSE_FILE="${COMPOSE_FILE:-$AUTH_ROOT/docker-compose.yml}"
export COMPOSE="${COMPOSE:-docker compose}"

export BACKEND_EXTERNAL_URL="${BACKEND_EXTERNAL_URL:-http://127.0.0.1:8080}"
export DASHBOARD_EXTERNAL_URL="${DASHBOARD_EXTERNAL_URL:-http://127.0.0.1:5173}"

REPORTS_DIR="$AUTH_ROOT/test/reports"
CONFIG_DIR="$AUTH_ROOT/test/config"
export REPORTS_DIR CONFIG_DIR

mkdir -p "$REPORTS_DIR"

# Docker host from other containers (ZAP, scanners). Linux may need: export DOCKER_HOST_ADDR=172.17.0.1
export DOCKER_HOST_ADDR="${DOCKER_HOST_ADDR:-host.docker.internal}"

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}
