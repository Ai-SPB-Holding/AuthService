#!/usr/bin/env python3
"""
Print `export KEY=...` lines for a small whitelist only (shlex-quoted).
Used instead of `source .env` so values with spaces (e.g. VITE_APP_NAME=Auth Admin)
do not break /bin/sh.
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path

# Only keys the security harness may read from .env (never export the whole file).
WHITELIST = frozenset(
    {
        "AUTH__ADMIN_API_AUDIENCE",
        "BACKEND_EXTERNAL_URL",
        "DASHBOARD_EXTERNAL_URL",
        "ESCALATION_TENANT_ID",
        "ESCALATION_REGULAR_EMAIL",
        "ESCALATION_REGULAR_PASSWORD",
        "ESCALATION_ADMIN_EMAIL",
        "ESCALATION_ADMIN_PASSWORD",
        "SECURITY_ESCALATION_SKIP",
    }
)


def parse_value(rest: str) -> str:
    rest = rest.strip()
    if not rest:
        return ""
    if rest.startswith('"'):
        if len(rest) >= 2 and rest.endswith('"') and rest.count('"') == 2:
            return rest[1:-1]
        # opening " ... find closing (minimal)
        out: list[str] = []
        i = 1
        while i < len(rest):
            c = rest[i]
            if c == "\\" and i + 1 < len(rest):
                out.append(rest[i + 1])
                i += 2
                continue
            if c == '"':
                break
            out.append(c)
            i += 1
        return "".join(out)
    if rest.startswith("'"):
        if len(rest) >= 2 and rest.endswith("'"):
            return rest[1:-1]
        end = rest.find("'", 1)
        return rest[1:end] if end != -1 else rest[1:]
    # Unquoted: entire RHS (Docker/.env style); do not split on spaces.
    return rest


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".env")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, rhs = line.partition("=")
        key = key.strip()
        if not key or key not in WHITELIST:
            continue
        val = parse_value(rhs)
        print(f"export {key}={shlex.quote(val)}")


if __name__ == "__main__":
    main()
