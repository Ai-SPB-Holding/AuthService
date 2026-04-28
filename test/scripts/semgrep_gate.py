#!/usr/bin/env python3
"""Fail if Semgrep JSON has ERROR (maps to high/critical policy) results."""
import json
import sys
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "test/reports/semgrep.json")
    if not path.exists() or path.stat().st_size == 0:
        print(f"Missing or empty {path}", file=sys.stderr)
        return 2
    data = json.loads(path.read_text(encoding="utf-8"))
    results = data.get("results") or []
    errors = [r for r in results if (r.get("extra") or {}).get("severity") == "ERROR"]
    if errors:
        ids = [r.get("check_id", "?") for r in errors[:20]]
        print(f"BLOCKED: Semgrep ERROR severity count={len(errors)} e.g. {ids!r}")
        return 1
    print(f"OK: Semgrep no ERROR findings ({len(results)} total)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
