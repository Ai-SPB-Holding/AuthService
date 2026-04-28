#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

echo "Stopping stack..."
make -f "$AUTH_ROOT/Makefile.docker" down
