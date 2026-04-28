#!/usr/bin/env python3
"""
Interactive TOTP enrollment: choose authenticator (Google, Microsoft, Authy, other),
enter API credentials, add account in the app, then type the 6-digit code.
Uses the same TOTP (RFC 6238) as the Auth Service; all listed apps are compatible.
"""
from __future__ import annotations

import getpass
import os
import sys

# Run as script: add repo scripts dir for imports
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import user_2fa_enroll as u  # noqa: E402

APPS: list[tuple[str, str]] = [
    (
        "google",
        "Google Authenticator\n"
        "  iOS/Android: + → Scan QR (if you transfer otpauth) or Enter a setup key → use 6-digit codes.",
    ),
    (
        "microsoft",
        "Microsoft Authenticator\n"
        "  + → Work or school account (or other) → sign in with setup key or paste otpauth, then 6-digit codes.",
    ),
    (
        "authy",
        "Authy\n"
        "  + → Enter key manually (base32) if the app asks, or add from QR on another device.",
    ),
    (
        "other",
        "Any TOTP app (1Password, Bitwarden, FreeOTP, …)\n"
        "  Add using the otpauth:// URL or the base32 secret shown below.",
    ),
]


def menu_apps() -> None:
    print("\n--- Authenticator (all use the same TOTP / time-based 6-digit codes) ---\n", file=sys.stderr)
    for i, (key, text) in enumerate(APPS, start=1):
        print(f"  [{i}] {text}\n", file=sys.stderr)
    print("  [5] Fast mode: server generates the code in this terminal (for automation, no phone).", file=sys.stderr)


def main() -> int:
    print("Auth Service — TOTP (2FA) setup\n", file=sys.stderr)
    base = (input(f"API URL [{os.environ.get('API_URL', 'http://localhost:8080')}]: ").strip() or None) or os.environ.get(
        "API_URL", "http://localhost:8080"
    )
    base = base.rstrip("/")
    tenant = input("Tenant UUID: ").strip()
    if not tenant:
        print("TENANT_ID is required", file=sys.stderr)
        return 1
    email = input("Email: ").strip()
    if not email:
        print("EMAIL is required", file=sys.stderr)
        return 1
    password = getpass.getpass("Password: ")
    if not password:
        print("PASSWORD is required", file=sys.stderr)
        return 1
    aud = (input(f"Audience [{os.environ.get('AUDIENCE', 'auth-service')}]: ").strip() or None) or os.environ.get(
        "AUDIENCE", "auth-service"
    )
    want_uid = input("Optional USER_ID to verify JWT sub (Enter to skip): ").strip()

    menu_apps()
    choice = (input("Choose [1-5, default=1]: ").strip() or "1").lower()
    fast = choice in ("5", "5.")

    if fast:
        print(
            "\nFast mode: verification uses the same 30s window as the new secret (for scripts / no phone).\n",
            file=sys.stderr,
        )
        return u.enroll_with_password(
            base,
            tenant,
            email,
            password,
            aud,
            want_uid,
            None,
        )
    print(
        "\nThe server will print otpauth + base32 — add the account in your app, then enter a code.\n",
        file=sys.stderr,
    )

    st, login = u.post_json(
        f"{base}/auth/login",
        {
            "tenant_id": tenant,
            "email": email,
            "password": password,
            "audience": aud,
        },
    )
    if st != 200:
        print(f"Login failed (HTTP {st}): {login}", file=sys.stderr)
        msg = login.get("error", login) if isinstance(login, dict) else login
        u.explain_login_2fa_block(msg)
        return 1
    if login.get("mfa_required"):
        print("mfa_required — complete MFA in the app first.", file=sys.stderr)
        return 1

    bearer: str
    if login.get("totp_enrollment_required") and login.get("enrollment_token"):
        bearer = str(login["enrollment_token"])
        print("Enrollment token (admin + global 2FA).", file=sys.stderr)
    else:
        at = login.get("access_token")
        if not at:
            print(f"No access_token: {login}", file=sys.stderr)
            return 1
        if want_uid and u.jwt_sub(str(at)) != want_uid:
            print("USER_ID mismatch (login access token).", file=sys.stderr)
            return 1
        bearer = str(at)

    st2, setup = u.post_json(
        f"{base}/2fa/setup",
        {},
        {"Authorization": f"Bearer {bearer}"},
    )
    if st2 != 200:
        print(f"POST /2fa/setup failed: {setup}", file=sys.stderr)
        return 1
    print("\n--- Add this account in your app ---\n", file=sys.stderr)
    print("otpauth_url:", setup.get("otpauth_url", ""), file=sys.stderr)
    print("secret_base32:", setup.get("secret_base32", ""), file=sys.stderr)
    print(file=sys.stderr)

    code = ""
    for _ in range(5):
        code = input("6-digit code from the app: ").strip().replace(" ", "")
        if len(code) == 6 and code.isdigit():
            break
        print("Please enter 6 digits.", file=sys.stderr)
    else:
        return 1

    st3, out = u.post_json(
        f"{base}/2fa/verify",
        {"code": code},
        {"Authorization": f"Bearer {bearer}"},
    )
    if st3 != 200:
        print(f"POST /2fa/verify failed (HTTP {st3}): {out}", file=sys.stderr)
        return 1
    if not out.get("ok") or not out.get("totp_enabled"):
        print(f"Unexpected response: {out}", file=sys.stderr)
        return 1

    if want_uid and isinstance(out, dict) and (at2 := out.get("access_token")):
        if u.jwt_sub(str(at2)) != want_uid:
            print("USER_ID mismatch (session after verify).", file=sys.stderr)
            return 1

    print("Done. TOTP is enabled for this user.", file=sys.stderr)
    return 0
