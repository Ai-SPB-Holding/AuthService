#!/usr/bin/env python3
"""
HTTP checks for access/refresh JWT lifetimes against a running AuthService.

Effective TTLs are clamped server-side (password login without OAuth client):
  access >= 60s, refresh >= 300s — see `resolve_effective_token_ttls_from_db_columns`
  in backend/src/services/auth_service.rs. Compose override values smaller than
  that still yield longer JWT lifetimes; timing uses API `expires_in` and JWT `exp`.

Flow:
  login -> userinfo(200) -> sleep past JWT exp + jsonwebtoken leeway (default 60s) + buffer
  -> userinfo(401)
  -> refresh(200) -> userinfo(200) -> refresh with pre-rotation token(401, revoked)
  -> sleep past refresh exp + leeway + buffer -> refresh(401)

The backend uses jsonwebtoken with default Validation.leeway=60, so a token is rejected only
when now > exp + 60 (see jsonwebtoken 9.x validation.rs).
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple


def jwt_payload_unverified(token: str) -> Dict[str, Any]:
    """Decode JWT payload (no signature verification; timing helper only)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token is not a JWT")
    payload_b64 = parts[1]
    pad = "=" * (-len(payload_b64) % 4)
    raw = base64.urlsafe_b64decode(payload_b64 + pad)
    return json.loads(raw.decode("utf-8"))


def http_json(
    method: str,
    url: str,
    body: Any = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
) -> Tuple[int, Any]:
    h = dict(headers or {})
    data: Optional[bytes] = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return resp.status, None
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed: object = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = {"_raw": raw}
        return e.code, parsed


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--base-url",
        default=os.environ.get("BACKEND_EXTERNAL_URL", "http://127.0.0.1:8080"),
    )
    p.add_argument(
        "--tenant-id",
        default=os.environ.get(
            "ESCALATION_TENANT_ID", "a1111111-1111-1111-1111-111111111111"
        ),
    )
    p.add_argument(
        "--email",
        default=os.environ.get(
            "ESCALATION_REGULAR_EMAIL", "security-escalation-probe@authservice.local"
        ),
    )
    p.add_argument(
        "--password",
        default=os.environ.get("ESCALATION_REGULAR_PASSWORD", "EscalationProbe2026!Secure"),
    )
    p.add_argument(
        "--admin-audience",
        default=os.environ.get("AUTH__ADMIN_API_AUDIENCE", "auth-service"),
    )
    p.add_argument(
        "--jwt-validation-leeway",
        type=float,
        default=float(os.environ.get("JWT_VALIDATION_LEEWAY_SEC", "60")),
        help="jsonwebtoken::Validation leeway (seconds); crate 9.x default is 60.",
    )
    p.add_argument(
        "--access-buffer-seconds",
        type=float,
        default=float(os.environ.get("JWT_TTL_ACCESS_BUFFER", "2")),
        help="Extra seconds after exp+leeway before expecting 401 on access.",
    )
    p.add_argument(
        "--refresh-buffer-seconds",
        type=float,
        default=float(os.environ.get("JWT_TTL_REFRESH_BUFFER", "2")),
        help="Extra seconds after refresh exp+leeway before expecting 401 on refresh.",
    )
    args = p.parse_args()

    base = args.base_url.rstrip("/")
    aud = args.admin_audience.strip()
    leeway = args.jwt_validation_leeway
    buf_a = args.access_buffer_seconds
    buf_r = args.refresh_buffer_seconds

    code, body = http_json(
        "POST",
        f"{base}/auth/login",
        {
            "tenant_id": args.tenant_id,
            "email": args.email,
            "password": args.password,
            "audience": aud,
        },
    )
    if code != 200:
        print(f"FAIL: POST /auth/login expected 200, got {code}: {body}", file=sys.stderr)
        return 1
    if not isinstance(body, dict):
        print(f"FAIL: login response not JSON object: {body}", file=sys.stderr)
        return 1
    if body.get("mfa_required") or body.get("totp_enrollment_required"):
        print(
            "FAIL: login returned MFA/TOTP challenge; use a user without MFA for this check.",
            file=sys.stderr,
        )
        return 1

    access = body.get("access_token")
    refresh = body.get("refresh_token")
    expires_in = body.get("expires_in")
    if not access or not refresh:
        print(f"FAIL: missing access_token or refresh_token: {body}", file=sys.stderr)
        return 1
    if expires_in is None:
        print(f"FAIL: login response missing expires_in: {body}", file=sys.stderr)
        return 1
    try:
        eff_access = float(expires_in)
    except (TypeError, ValueError):
        print(f"FAIL: invalid expires_in: {expires_in}", file=sys.stderr)
        return 1

    try:
        a_payload = jwt_payload_unverified(access)
        a_exp = float(a_payload["exp"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as e:
        print(f"FAIL: could not read exp from access JWT: {e}", file=sys.stderr)
        return 1

    code, _u = http_json(
        "GET",
        f"{base}/oauth2/userinfo",
        headers={"Authorization": f"Bearer {access}"},
    )
    if code != 200:
        print(
            f"FAIL: GET /oauth2/userinfo (fresh access) expected 200, got {code}",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-jwt-ttl: expires_in={int(eff_access)}s, access JWT exp in "
        f"{max(0.0, a_exp - time.time()):.1f}s; waiting until past exp+leeway "
        f"({int(leeway)}s, jsonwebtoken default) + buffer …",
        file=sys.stderr,
    )
    wait_acc = a_exp + leeway + buf_a - time.time()
    if wait_acc > 0:
        time.sleep(wait_acc)
    code, _u = http_json(
        "GET",
        f"{base}/oauth2/userinfo",
        headers={"Authorization": f"Bearer {access}"},
    )
    if code != 401:
        print(
            f"FAIL: GET /oauth2/userinfo (expired access) expected 401, got {code}",
            file=sys.stderr,
        )
        return 1

    code, body = http_json(
        "POST",
        f"{base}/auth/refresh",
        {"refresh_token": refresh, "audience": aud},
    )
    if code != 200:
        print(f"FAIL: POST /auth/refresh expected 200, got {code}: {body}", file=sys.stderr)
        return 1
    if not isinstance(body, dict):
        print(f"FAIL: refresh response not JSON object: {body}", file=sys.stderr)
        return 1
    access2 = body.get("access_token")
    refresh2 = body.get("refresh_token")
    if not access2 or not refresh2:
        print(f"FAIL: refresh missing tokens: {body}", file=sys.stderr)
        return 1
    try:
        r_payload = jwt_payload_unverified(refresh2)
        r_exp = r_payload.get("exp")
        if r_exp is None:
            print(f"FAIL: refresh JWT missing exp: {r_payload}", file=sys.stderr)
            return 1
        r_exp_f = float(r_exp)
    except (ValueError, json.JSONDecodeError, KeyError) as e:
        print(f"FAIL: could not decode refresh JWT: {e}", file=sys.stderr)
        return 1

    print(
        f"check-jwt-ttl: rotated refresh JWT exp in {max(0.0, r_exp_f - time.time()):.1f}s "
        f"(server min refresh 300s for typical login); then wait exp+leeway+buffer …",
        file=sys.stderr,
    )

    code, _u = http_json(
        "GET",
        f"{base}/oauth2/userinfo",
        headers={"Authorization": f"Bearer {access2}"},
    )
    if code != 200:
        print(
            f"FAIL: GET /oauth2/userinfo (after rotate) expected 200, got {code}",
            file=sys.stderr,
        )
        return 1

    code, _b = http_json(
        "POST",
        f"{base}/auth/refresh",
        {"refresh_token": refresh, "audience": aud},
    )
    if code != 401:
        print(
            f"FAIL: POST /auth/refresh with pre-rotation refresh expected 401, got {code}",
            file=sys.stderr,
        )
        return 1

    wait_ref = r_exp_f + leeway + buf_r - time.time()
    if wait_ref > 0:
        time.sleep(wait_ref)

    code, _b = http_json(
        "POST",
        f"{base}/auth/refresh",
        {"refresh_token": refresh2, "audience": aud},
    )
    if code != 401:
        print(
            f"FAIL: POST /auth/refresh (expired refresh JWT) expected 401, got {code}",
            file=sys.stderr,
        )
        return 1

    print("check-jwt-ttl: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
