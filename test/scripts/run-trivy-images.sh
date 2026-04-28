#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

echo "Building images for Trivy..."
$COMPOSE -f "$COMPOSE_FILE" build backend dashboard-ui

mkdir -p "$REPORTS_DIR/trivy"

# Compose default project name: directory basename lowercased (unless COMPOSE_PROJECT_NAME is set).
compose_project_slug() {
	if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
		printf %s "$COMPOSE_PROJECT_NAME"
		return
	fi
	basename "$AUTH_ROOT" | tr '[:upper:]' '[:lower:]'
}

resolve_image() {
	svc="$1"
	img="$($COMPOSE -f "$COMPOSE_FILE" images -q "$svc" 2>/dev/null | head -n1 || true)"
	# `compose images -q` is often empty when the stack is not running; after `compose build` the image still exists.
	if [ -z "$img" ]; then
		proj="$(compose_project_slug)"
		img="$(docker images -q \
			--filter "label=com.docker.compose.project=${proj}" \
			--filter "label=com.docker.compose.service=${svc}" \
			2>/dev/null | head -n1 || true)"
	fi
	if [ -z "$img" ]; then
		proj="$(compose_project_slug)"
		for ref in "${proj}-${svc}:latest" "${proj}_${svc}:latest" "${proj}-${svc}" "${proj}_${svc}"; do
			id="$(docker images -q "$ref" 2>/dev/null | head -n1 || true)"
			if [ -n "$id" ]; then
				img="$id"
				break
			fi
		done
	fi
	if [ -z "$img" ]; then
		echo "Could not resolve docker image for service '$svc' (run compose build from repo root; try: export COMPOSE_PROJECT_NAME=...)" >&2
		exit 1
	fi
	printf %s "$img"
}

trivy_fail=0
for svc in backend dashboard-ui; do
	img="$(resolve_image "$svc")"
	echo "Trivy scan service=$svc image=$img"
	if ! docker run --rm \
		-v "$REPORTS_DIR/trivy:/out" \
		-v "$CONFIG_DIR/.trivyignore:/work/.trivyignore:ro" \
		-v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy:latest image \
		--severity HIGH,CRITICAL \
		--exit-code 1 \
		--ignorefile /work/.trivyignore \
		--format json \
		-o "/out/${svc}.json" \
		"$img"; then
		trivy_fail=1
	fi
done

if [ "$trivy_fail" != "0" ]; then
	echo "BLOCKED: Trivy found HIGH/CRITICAL (see $REPORTS_DIR/trivy/)" >&2
	exit 1
fi
echo "OK: Trivy image scan passed."
