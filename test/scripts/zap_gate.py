#!/usr/bin/env python3
"""
Fail if ZAP JSON report contains High or Critical risk anywhere
(riskdesc / riskcode in common ZAP baseline exports).
"""
import json
import sys
from pathlib import Path


def risk_is_bad(alert: dict) -> bool:
    rd = str(alert.get("riskdesc") or alert.get("risk") or "").strip().lower()
    if rd in ("high", "critical"):
        return True
    rc = alert.get("riskcode")
    if rc in (3, 4, "3", "4"):
        return True
    return False


def looks_like_zap_alert(d: dict) -> bool:
    return ("pluginid" in d or "alert" in d) and ("riskdesc" in d or "riskcode" in d)


def walk(obj, bad: list) -> None:
    if isinstance(obj, dict):
        if looks_like_zap_alert(obj) and risk_is_bad(obj):
            bad.append(obj.get("alert") or obj.get("name") or obj.get("pluginid") or "?")
        for v in obj.values():
            walk(v, bad)
    elif isinstance(obj, list):
        for x in obj:
            walk(x, bad)


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "test/reports/zap-backend.json")
    if not path.exists():
        print(f"Missing {path}", file=sys.stderr)
        return 2
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    bad: list = []
    walk(data, bad)
    if bad:
        print(f"BLOCKED: ZAP High/Critical ({len(bad)}): {bad[:20]!r} — see {path}")
        return 1
    print(f"OK: ZAP no High/Critical in {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
