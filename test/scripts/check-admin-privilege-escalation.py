#!/usr/bin/env python3
"""
Negative checks: a non-admin user must not obtain admin JWT claims or call /admin/* routes
protected by require_admin.

Exit codes:
  0 — all checks passed (no illegal admin / no forbidden admin API access)
  1 — vulnerability or unexpected success on a protected admin route
  2 — setup error (login failed, bad args, network)

Requires a real user without the `admin` role (and not in AUTH__GLOBAL_ADMIN_USER_IDS if you
care about deployment-global scope). Stack must be up.
"""
from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any


def jwt_payload_unverified(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    payload_b64 = parts[1]
    pad = "=" * ((4 - len(payload_b64) % 4) % 4)
    raw = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
    return json.loads(raw.decode("utf-8"))


def http_json(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    ctx: ssl.SSLContext | None = None,
) -> tuple[int, dict[str, Any] | list[Any] | str]:
    data = None
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            sc = resp.getcode()
            text = resp.read().decode("utf-8", errors="replace")
            try:
                return sc, json.loads(text)
            except json.JSONDecodeError:
                return sc, text
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")
        try:
            parsed: dict[str, Any] | list[Any] | str = json.loads(text)
        except json.JSONDecodeError:
            parsed = text
        return e.code, parsed


def fail_vuln(msg: str) -> None:
    print(f"FAIL (privilege / authz): {msg}", file=sys.stderr)
    sys.exit(1)


def fail_setup(msg: str) -> None:
    print(f"ERROR (setup): {msg}", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://127.0.0.1:8080")
    p.add_argument("--tenant-id", required=True)
    p.add_argument("--email", required=True, help="User that must NOT have admin role")
    p.add_argument("--password", required=True)
    p.add_argument(
        "--admin-audience",
        default="auth-service",
        help="Must match AUTH__ADMIN_API_AUDIENCE (same as dashboard login audience).",
    )
    p.add_argument(
        "--wrong-audience",
        default="non-admin-resource-audience-test",
        help="Audience string that is not the admin API audience.",
    )
    p.add_argument(
        "--admin-email",
        default="",
        help="Optional: if set with --admin-password, positive check (admin can GET /admin/users).",
    )
    p.add_argument("--admin-password", default="")
    p.add_argument(
        "--insecure-tls",
        action="store_true",
        help="Allow self-signed HTTPS (dev only).",
    )
    args = p.parse_args()
    base = args.base_url.rstrip("/")
    ctx = None
    if args.insecure_tls and base.lower().startswith("https"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    # --- Non-admin login with admin API audience (same as dashboard) ---
    sc, login_body = http_json(
        "POST",
        f"{base}/auth/login",
        {
            "tenant_id": args.tenant_id,
            "email": args.email,
            "password": args.password,
            "audience": args.admin_audience,
        },
        ctx=ctx,
    )
    if sc != 200:
        fail_setup(f"login returned {sc}: {login_body!r}")
    if not isinstance(login_body, dict) or "access_token" not in login_body:
        fail_setup(f"login JSON missing access_token: {login_body!r}")

    access = str(login_body["access_token"])
    try:
        claims = jwt_payload_unverified(access)
    except (ValueError, json.JSONDecodeError) as e:
        fail_setup(f"cannot parse access JWT: {e}")

    roles = claims.get("roles") or []
    if not isinstance(roles, list):
        fail_setup(f"unexpected roles type in JWT: {roles!r}")
    if "admin" in roles:
        fail_vuln("JWT contains admin role for user that must be non-admin")

    auth_h = {"Authorization": f"Bearer {access}"}

    # require_admin routes — must not return 2xx
    admin_only_paths = [
        ("GET", f"{base}/admin/users"),
        ("GET", f"{base}/admin/rbac"),
        ("GET", f"{base}/admin/dashboard/stats"),
    ]
    for method, path in admin_only_paths:
        sc2, _ = http_json(method, path, headers=auth_h, ctx=ctx)
        if 200 <= sc2 < 300:
            fail_vuln(f"{method} {path} returned {sc2} with non-admin token")

    # POST /auth/register: explicit bearer check (admin role required)
    sc_reg, _ = http_json(
        "POST",
        f"{base}/auth/register",
        {
            "tenant_id": args.tenant_id,
            "email": "escalation-probe@invalid.local",
            "password": "NotUsed123456",
        },
        headers=auth_h,
        ctx=ctx,
    )
    if 200 <= sc_reg < 300:
        fail_vuln(f"POST /auth/register returned {sc_reg} with non-admin token")

    # require_admin_audience only — session must admit user but not claim admin
    sc_sess, sess_body = http_json("GET", f"{base}/admin/session", headers=auth_h, ctx=ctx)
    if sc_sess != 200 or not isinstance(sess_body, dict):
        fail_setup(f"GET /admin/session unexpected {sc_sess}: {sess_body!r}")
    if sess_body.get("is_admin") is True:
        fail_vuln("GET /admin/session reports is_admin=true for non-admin user")
    if sess_body.get("is_deployment_global_admin") is True:
        fail_vuln(
            "GET /admin/session reports is_deployment_global_admin=true — "
            "use a user not listed in AUTH__GLOBAL_ADMIN_USER_IDS"
        )

    # Wrong audience: token must not work against admin API
    sc_w, login_w = http_json(
        "POST",
        f"{base}/auth/login",
        {
            "tenant_id": args.tenant_id,
            "email": args.email,
            "password": args.password,
            "audience": args.wrong_audience,
        },
        ctx=ctx,
    )
    if sc_w != 200 or not isinstance(login_w, dict) or "access_token" not in login_w:
        fail_setup(f"wrong-audience login failed {sc_w}: {login_w!r}")
    wrong_token = str(login_w["access_token"])
    sc_users_wrong, _ = http_json(
        "GET",
        f"{base}/admin/users",
        headers={"Authorization": f"Bearer {wrong_token}"},
        ctx=ctx,
    )
    if 200 <= sc_users_wrong < 300:
        fail_vuln(
            f"GET /admin/users returned {sc_users_wrong} with token aud={args.wrong_audience!r}"
        )

    # Optional positive control
    if args.admin_email and args.admin_password:
        sc_a, login_a = http_json(
            "POST",
            f"{base}/auth/login",
            {
                "tenant_id": args.tenant_id,
                "email": args.admin_email,
                "password": args.admin_password,
                "audience": args.admin_audience,
            },
            ctx=ctx,
        )
        if sc_a != 200:
            fail_setup(f"admin login failed {sc_a}: {login_a!r}")
        if not isinstance(login_a, dict) or "access_token" not in login_a:
            fail_setup(f"admin login bad body: {login_a!r}")
        admin_access = str(login_a["access_token"])
        ac = jwt_payload_unverified(admin_access)
        ar = ac.get("roles") or []
        if "admin" not in ar:
            fail_setup("positive check: admin user JWT has no admin role (wrong fixture?)")
        sc_list, _ = http_json(
            "GET",
            f"{base}/admin/users",
            headers={"Authorization": f"Bearer {admin_access}"},
            ctx=ctx,
        )
        if sc_list != 200:
            fail_setup(f"positive check: GET /admin/users expected 200 got {sc_list}")

    print("OK: no admin escalation; require_admin routes blocked for non-admin user.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
