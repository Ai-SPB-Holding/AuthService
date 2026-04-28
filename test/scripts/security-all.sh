#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

on_abort() {
	rc=$?
	echo "Aborted (exit $rc). Stack may still be running; use: make -f Makefile.test security-down" >&2
	exit "$rc"
}
trap on_abort INT TERM

sh "$SCRIPT_DIR/run-gitleaks.sh"
sh "$SCRIPT_DIR/run-semgrep.sh"
sh "$SCRIPT_DIR/run-npm-audit.sh"
sh "$SCRIPT_DIR/run-cargo-audit.sh"

sh "$SCRIPT_DIR/security-up.sh"
sh "$SCRIPT_DIR/run-internal-smoke.sh"
sh "$SCRIPT_DIR/run-headers-check.sh"
sh "$SCRIPT_DIR/run-security-escalation.sh"
sh "$SCRIPT_DIR/run-zap-baseline.sh"
sh "$SCRIPT_DIR/run-trivy-images.sh"

echo "security-all: completed successfully. Teardown: make -f Makefile.test security-down"
trap - INT TERM
