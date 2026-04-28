#!/usr/bin/env python3
"""
Fail if cargo-audit JSON lists advisories with severity high/critical
or CVSS score >= 7.0. Advisories without CVSS/severity are ignored for gating
(align with High/Critical only); see RUSTSEC text in report for triage.
"""
import json
import sys
from pathlib import Path


def advisory_bad(adv: dict) -> bool:
    sev = (adv.get("severity") or "").strip().lower()
    if sev in ("high", "critical"):
        return True
    cvss = adv.get("cvss")
    if isinstance(cvss, dict):
        score = cvss.get("score")
        if score is not None:
            try:
                return float(score) >= 7.0
            except (TypeError, ValueError):
                pass
    return False


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "test/reports/cargo-audit.json")
    if not path.exists():
        print(f"Missing {path}", file=sys.stderr)
        return 2
    data = json.loads(path.read_text(encoding="utf-8"))

    vulns = (data.get("vulnerabilities") or {}).get("list") or []
    bad = []
    for item in vulns:
        adv = item.get("advisory") or {}
        if advisory_bad(adv):
            bad.append(adv.get("id", "?"))

    if bad:
        print(f"BLOCKED: cargo-audit high/critical CVSS>=7: {', '.join(bad)} (see {path})")
        return 1
    print("OK: cargo-audit no high/critical (by severity/CVSS>=7)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
