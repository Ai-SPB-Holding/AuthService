#!/usr/bin/env sh
set -e
. "$(dirname "$0")/common.sh"

url="${1:?usage: wait-for-http.sh URL [max_seconds]}"
max="${2:-120}"
i=0
echo "Waiting for $url (max ${max}s)..."
while [ "$i" -lt "$max" ]; do
	if have_cmd curl; then
		if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
			echo "OK: $url"
			exit 0
		fi
	elif have_cmd wget; then
		if wget -q -T 3 -O /dev/null "$url" 2>/dev/null; then
			echo "OK: $url"
			exit 0
		fi
	else
		echo "Need curl or wget" >&2
		exit 1
	fi
	i=$((i + 2))
	sleep 2
done
echo "Timeout waiting for $url" >&2
exit 1
