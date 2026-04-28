#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

if [ "${SKIP_CARGO_AUDIT:-}" = "1" ]; then
	echo "SKIP_CARGO_AUDIT=1 — skipping cargo-audit"
	exit 0
fi

if have_cmd cargo && have_cmd cargo-audit; then
	echo "Using host cargo-audit..."
	set +e
	cargo audit --json >"$REPORTS_DIR/cargo-audit.json" 2>"$REPORTS_DIR/cargo-audit.stderr"
	_ec=$?
	set -e
	if [ ! -s "$REPORTS_DIR/cargo-audit.json" ]; then
		echo "cargo-audit produced no JSON (exit $_ec). stderr:" >&2
		cat "$REPORTS_DIR/cargo-audit.stderr" >&2 2>/dev/null || true
		exit 1
	fi
else
	echo "Running cargo-audit in Docker (first run may download toolchain)..."
	docker run --rm \
		-v "$AUTH_ROOT:/workspace:rw" \
		-w /workspace \
		-e CARGO_HOME=/tmp/cargohome \
		rust:1.88-bookworm \
		bash -c '
			# bash -lc resets PATH via /root/.profile; keep rustup + installed plugins on PATH
			export PATH="/tmp/cargohome/bin:/usr/local/cargo/bin:${PATH}"
			set -e
			mkdir -p /tmp/cargohome test/reports
			apt-get update -qq && apt-get install -y -qq pkg-config libssl-dev git ca-certificates >/dev/null
			# 0.21.x fails on advisories with CVSS 4.0 (e.g. RUSTSEC-2026-0003)
			cargo install cargo-audit --version 0.22.1 --locked
			set +e
			cargo audit --json > test/reports/cargo-audit.json 2> test/reports/cargo-audit.stderr
			_ec=$?
			set -e
			if [ ! -s test/reports/cargo-audit.json ]; then
				echo "cargo-audit produced no JSON (exit=$_ec). stderr:" >&2
				cat test/reports/cargo-audit.stderr >&2
				exit 1
			fi
			exit 0
		'
fi

python3 "$SCRIPT_DIR/cargo_audit_gate.py" "$REPORTS_DIR/cargo-audit.json"
