#!/usr/bin/env sh
# Passive baseline: external (host ports) + internal (backend container NS).
# ZAP Docker image requires a *directory* mounted at /zap/wrk for -J/-r/-c (see ZAP baseline docs).
# Pass -J/-r as basenames only: the Automation Framework prepends /zap/wrk/ and absolute paths double it.
set -e
. "$(dirname "$0")/common.sh"

EXTRA_DOCKER=""
case "$(uname -s 2>/dev/null)" in
Linux) EXTRA_DOCKER="--add-host=host.docker.internal:host-gateway" ;;
esac

USE_RULES=0
if grep -v '^#' "$CONFIG_DIR/zap-baseline-rules.tsv" 2>/dev/null | grep -q '[^[:space:]]'; then
	USE_RULES=1
fi

run_zap() {
	name="$1"
	target="$2"
	json_out="$3"
	html_out="$4"
	net="$5"
	echo "ZAP baseline: $name -> $target"
	set +e
	if [ -n "$net" ] && [ "$USE_RULES" -eq 1 ]; then
		# shellcheck disable=SC2086
		docker run --rm --network "$net" $EXTRA_DOCKER \
			-v "$REPORTS_DIR:/zap/wrk:rw" \
			-v "$CONFIG_DIR/zap-baseline-rules.tsv:/zap/wrk/rules.tsv:ro" \
			ghcr.io/zaproxy/zaproxy:stable \
			zap-baseline.py -t "$target" -c rules.tsv \
			-J "$json_out" -r "$html_out"
	elif [ -n "$net" ]; then
		# shellcheck disable=SC2086
		docker run --rm --network "$net" $EXTRA_DOCKER \
			-v "$REPORTS_DIR:/zap/wrk:rw" \
			ghcr.io/zaproxy/zaproxy:stable \
			zap-baseline.py -t "$target" \
			-J "$json_out" -r "$html_out"
	elif [ "$USE_RULES" -eq 1 ]; then
		# shellcheck disable=SC2086
		docker run --rm $EXTRA_DOCKER \
			-v "$REPORTS_DIR:/zap/wrk:rw" \
			-v "$CONFIG_DIR/zap-baseline-rules.tsv:/zap/wrk/rules.tsv:ro" \
			ghcr.io/zaproxy/zaproxy:stable \
			zap-baseline.py -t "$target" -c rules.tsv \
			-J "$json_out" -r "$html_out"
	else
		# shellcheck disable=SC2086
		docker run --rm $EXTRA_DOCKER \
			-v "$REPORTS_DIR:/zap/wrk:rw" \
			ghcr.io/zaproxy/zaproxy:stable \
			zap-baseline.py -t "$target" \
			-J "$json_out" -r "$html_out"
	fi
	zec=$?
	set -e
	# ZAP: 0=pass, 1=warnings, 2=fail. We gate High/Critical via JSON.
	if [ ! -f "$REPORTS_DIR/$json_out" ]; then
		echo "ZAP did not write $json_out (docker exit $zec)" >&2
		return 1
	fi
	python3 "$SCRIPT_DIR/zap_gate.py" "$REPORTS_DIR/$json_out"
}

run_zap "backend-health-ext" "http://${DOCKER_HOST_ADDR}:8080/health" "zap-ext-backend.json" "zap-ext-backend.html" "" || exit 1
run_zap "backend-oidc-ext" "http://${DOCKER_HOST_ADDR}:8080/.well-known/openid-configuration" "zap-ext-oidc.json" "zap-ext-oidc.html" "" || exit 1
run_zap "dashboard-root-ext" "http://${DOCKER_HOST_ADDR}:5173/" "zap-ext-dashboard.json" "zap-ext-dashboard.html" "" || exit 1

if docker inspect auth-backend >/dev/null 2>&1; then
	run_zap "backend-health-int" "http://127.0.0.1:8080/health" "zap-int-backend.json" "zap-int-backend.html" "container:auth-backend" || exit 1
else
	echo "WARN: container auth-backend not running; skip internal ZAP" >&2
fi

echo "OK: ZAP baseline stages passed."
