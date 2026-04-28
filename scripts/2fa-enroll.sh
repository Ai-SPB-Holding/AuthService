#!/usr/bin/env sh
# Wraps user_2fa_enroll.py so Makefile does not depend on GNU $(MAKEFILE_LIST) for paths.
set -e
here="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
exec python3 "$here/user_2fa_enroll.py" "$@"
