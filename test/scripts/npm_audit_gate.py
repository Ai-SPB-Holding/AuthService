#!/usr/bin/env python3
"""Fail if npm audit JSON reports high or critical vulnerabilities."""
import json
import sys
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "test/reports/npm-audit.json")
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in {path}: {e}", file=sys.stderr)
        return 2

    if data.get("error"):
        print(f"npm audit error: {data.get('error')}", file=sys.stderr)
        return 2

    meta = data.get("metadata") or {}
    vuln = meta.get("vulnerabilities") or {}
    high = int(vuln.get("high") or 0)
    crit = int(vuln.get("critical") or 0)
    if high > 0 or crit > 0:
        print(f"BLOCKED: npm audit high={high} critical={crit} (see {path})")
        return 1
    print(f"OK: npm audit high={high} critical={crit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
