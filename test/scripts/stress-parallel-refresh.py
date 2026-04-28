#!/usr/bin/env python3
"""
Stress parallel POST /auth/refresh with the same refresh_token (race detector).

Usage (from repo root, stack up):
  python3 test/scripts/stress-parallel-refresh.py \
    --base-url http://127.0.0.1:8080 \
    --tenant-id 11111111-1111-1111-1111-111111111111 \
    --email audit-admin@local.test \
    --password 'AuditTest#2026' \
    --audience auth-service \
    --trials 40

Exit 1 if any trial returns all HTTP 200 in parallel (e.g. two workers both 200) — regression guard after refresh rotation fix.
Exit 2 if login fails (wrong credentials, 429 rate limit, etc.).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import urllib.error
import urllib.request


def post_json(url: str, body: dict) -> tuple[int, str]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://127.0.0.1:8080")
    p.add_argument("--tenant-id", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--audience", default="auth-service")
    p.add_argument("--trials", type=int, default=30)
    p.add_argument("--workers", type=int, default=2)
    p.add_argument(
        "--allow-double-200",
        action="store_true",
        help="Do not fail if parallel refresh race detected (for local investigation only).",
    )
    args = p.parse_args()
    base = args.base_url.rstrip("/")

    bad = 0
    for t in range(args.trials):
        sc, login_body = post_json(
            f"{base}/auth/login",
            {
                "tenant_id": args.tenant_id,
                "email": args.email,
                "password": args.password,
                "audience": args.audience,
            },
        )
        if sc != 200:
            print(f"trial {t}: login {sc} {login_body[:200]!r}", file=sys.stderr)
            return 2
        rt = json.loads(login_body)["refresh_token"]

        def refresh(_: int) -> int:
            c, _ = post_json(f"{base}/auth/refresh", {"refresh_token": rt})
            return c

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            codes = list(ex.map(refresh, range(args.workers)))
        if all(c == 200 for c in codes):
            print(f"DOUBLE_200 trial={t} codes={codes}")
            bad += 1
        elif t % 10 == 0:
            print(f"trial {t} codes={codes}")

    pct = 100.0 * bad / args.trials if args.trials else 0.0
    print(f"summary: double_200_batches={bad}/{args.trials} ({pct:.2f}%)")
    if bad and not args.allow_double_200:
        print("FAIL: parallel refresh race (all workers returned 200)")
        return 1
    if bad:
        print("WARN: double-200 observed but --allow-double-200 set")
    print("OK: no parallel refresh race detected (or allowed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
