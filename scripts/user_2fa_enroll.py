#!/usr/bin/env python3
"""
Enroll TOTP (Google Authenticator) for a user via the Auth Service HTTP API:
  POST /auth/login -> POST /2fa/setup -> POST /2fa/verify

Env / args: API URL, tenant, email, password, audience, optional --expect-user-id for a safety check.

Requires: same network as the API. If AUTH__REQUIRE_LOGIN_2FA is on and the user is not
«admin», password login is rejected (chicken-and-egg): grant admin first or temporarily
disable the flag. Admins get enrollment_token on login; this script now completes that flow.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def b32_totp_code(secret_b32: str) -> str:
    import base64
    import hmac
    import hashlib
    import struct
    import time

    s = secret_b32.strip().replace(" ", "").upper()
    pad = "=" * ((8 - len(s) % 8) % 8)
    key = base64.b32decode(s + pad)
    counter = int(time.time()) // 30
    msg = struct.pack(">Q", counter)
    dig = hmac.new(key, msg, hashlib.sha1).digest()
    off = dig[-1] & 0x0F
    n = struct.unpack(">I", dig[off : off + 4])[0] & 0x7FFFFFFF
    return f"{n % 1_000_000:06d}"


def jwt_sub(token: str) -> str:
    import base64

    p = token.split(".")[1]
    p += "=" * ((4 - len(p) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(p.encode("ascii")))
    return str(payload.get("sub", ""))


def post_json(url: str, body: object, headers: dict[str, str] | None = None) -> tuple[int, object]:
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 — user-supplied dev URL
            raw = resp.read().decode("utf-8")
            st = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        st = e.code
    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {"_raw": raw}
    return st, parsed


def explain_login_2fa_block(err: object) -> None:
    s = str(err) if not isinstance(err, str) else err
    if "REQUIRE_LOGIN_2FA" in s or "enroll user TOTP" in s:
        print(
            "\n  Why: AUTH__REQUIRE_LOGIN_2FA is on, TOTP is not set yet, and this user is not in "
            "the `admin` role — password login is blocked (no way to get a session).\n"
            "  Fix one of:\n"
            "    1) Promote to admin, then re-run: "
            "make -f Makefile.users user-promote-admin TENANT_ID=... USER_ID=... — "
            "login then returns an enrollment token and this script can finish TOTP.\n"
            "    2) Set AUTH__REQUIRE_LOGIN_2FA=false temporarily, run user-2fa-init, set it back to true.\n"
            "    3) Use the dashboard login flow (admins get a forced TOTP setup step when the flag is on).\n",
            file=sys.stderr,
        )


def run_totp_setup_verify(
    base: str,
    bearer: str,
    verify_code: str | None = None,
) -> tuple[int, object]:
    """If verify_code is None, computes TOTP from server secret (headless / CI). Otherwise uses the given 6 digits (e.g. from a phone app). Returns (0, out) on success."""
    st2, setup = post_json(
        f"{base}/2fa/setup",
        {},
        {"Authorization": f"Bearer {bearer}"},
    )
    if st2 != 200:
        print(f"POST /2fa/setup failed (HTTP {st2}): {setup}", file=sys.stderr)
        return 1, setup
    secret = setup.get("secret_base32")
    if not secret:
        print(f"No secret_base32: {setup}", file=sys.stderr)
        return 1, setup
    otpauth = setup.get("otpauth_url", "")
    print("otpauth_url:", otpauth, file=sys.stderr)
    print("secret_base32 (save offline):", secret, file=sys.stderr)

    if verify_code is None:
        code = b32_totp_code(secret)
        print("Verifying TOTP (auto-generated, same 30s window) …", file=sys.stderr)
    else:
        c = verify_code.strip()
        if len(c) != 6 or not c.isdigit():
            print("Verification code must be 6 digits.", file=sys.stderr)
            return 1, {}
        code = c
        print("Verifying TOTP (code from your authenticator) …", file=sys.stderr)

    st3, out = post_json(
        f"{base}/2fa/verify",
        {"code": code},
        {"Authorization": f"Bearer {bearer}"},
    )
    if st3 != 200:
        print(f"POST /2fa/verify failed (HTTP {st3}): {out}", file=sys.stderr)
        return 1, out
    if not out.get("ok") or not out.get("totp_enabled"):
        print(f"Unexpected verify response: {out}", file=sys.stderr)
        return 1, out
    print("2FA is enabled (totp_enabled=true).", file=sys.stderr)
    return 0, out


def enroll_with_password(
    base: str,
    tenant_id: str,
    email: str,
    password: str,
    audience: str,
    want_uid: str,
    verify_code: str | None = None,
) -> int:
    """Full flow: login → 2fa setup+verify. verify_code only used after setup; None = auto TOTP from secret."""
    st, login = post_json(
        f"{base}/auth/login",
        {
            "tenant_id": tenant_id,
            "email": email,
            "password": password,
            "audience": audience,
        },
    )
    if st != 200:
        print(f"Login failed (HTTP {st}): {login}", file=sys.stderr)
        msg = login.get("error", login) if isinstance(login, dict) else login
        explain_login_2fa_block(msg)
        return 1
    if login.get("mfa_required"):
        print("Login returned mfa_required; finish MFA in the app first.", file=sys.stderr)
        return 1
    if login.get("totp_enrollment_required") and login.get("enrollment_token"):
        et = str(login["enrollment_token"])
        print("Using totp_enrollment token (admin, global 2FA on, TOTP not set yet).", file=sys.stderr)
        rc, out = run_totp_setup_verify(base, et, verify_code)
        if rc != 0:
            return 1
        if want_uid and isinstance(out, dict):
            at2 = out.get("access_token")
            if at2 and jwt_sub(str(at2)) != want_uid:
                print(
                    f"USER_ID mismatch: access sub is {jwt_sub(str(at2))}, expected {want_uid}",
                    file=sys.stderr,
                )
                return 1
        return 0

    at = login.get("access_token")
    if not at:
        print(f"No access_token: {login}", file=sys.stderr)
        return 1
    if want_uid:
        sub = jwt_sub(str(at))
        if sub != want_uid:
            print(f"USER_ID mismatch: token sub is {sub}, expected {want_uid}", file=sys.stderr)
            return 1

    rc, _ = run_totp_setup_verify(base, str(at), verify_code)
    return rc


def main() -> int:
    p = argparse.ArgumentParser(description="Enroll TOTP for a user (dev / ops).")
    p.add_argument("--api-url", default=os.environ.get("API_URL", "http://localhost:8080"), help="Auth API base URL")
    p.add_argument("--tenant-id", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--audience", default=os.environ.get("AUDIENCE", "auth-service"))
    p.add_argument(
        "--expect-user-id",
        default="",
        help="If set, assert access JWT sub (after session) matches this UUID",
    )
    p.add_argument(
        "--code",
        default="",
        help="6-digit TOTP from your app (optional). If omitted, code is generated automatically for headless use.",
    )
    args = p.parse_args()
    base = args.api_url.rstrip("/")
    want_uid = (args.expect_user_id or "").strip()
    manual = (args.code or "").strip()
    vcode: str | None = manual if len(manual) == 6 and manual.isdigit() else None
    if manual and vcode is None:
        print("--code must be exactly 6 digits", file=sys.stderr)
        return 1

    return enroll_with_password(
        base,
        args.tenant_id,
        args.email,
        args.password,
        args.audience,
        want_uid,
        vcode,
    )


if __name__ == "__main__":
    sys.exit(main())
