#!/usr/bin/env sh
# Run from AuthService repo root, or: sh scripts/2fa-menu.sh
set -e
here="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
exec python3 "$here/user_2fa_enroll_interactive.py"
