#!/usr/bin/env python3
"""Small client example for Auth Service login/refresh/logout flow.

Usage:
  python auth_via_example.py \
    --base-url https://example \
    --tenant-id 00000000-0000-0000-0000-000000000001 \
    --email admin@example.com \
    --password 'AdminPass123!' \
    --audience auth-service
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int


class AuthClient:
    def __init__(self, base_url: str, timeout_seconds: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.timeout_seconds = timeout_seconds

    def login(self, tenant_id: str, email: str, password: str, audience: str) -> TokenPair:
        payload = {
            "tenant_id": tenant_id,
            "email": email,
            "password": password,
            "audience": audience,
        }
        data = self._post_json("/auth/login", payload)
        return self._to_token_pair(data)

    def refresh(self, refresh_token: str, audience: str) -> TokenPair:
        payload = {
            "refresh_token": refresh_token,
            "audience": audience,
        }
        data = self._post_json("/auth/refresh", payload)
        return self._to_token_pair(data)

    def userinfo(self, access_token: str, audience: str) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = self.session.get(
            f"{self.base_url}/userinfo",
            params={"audience": audience},
            headers=headers,
            timeout=self.timeout_seconds,
        )
        return self._decode_response(response)

    def logout(self, refresh_token: str) -> dict[str, Any]:
        payload = {"refresh_token": refresh_token}
        return self._post_json("/auth/logout", payload)

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}{path}",
            json=payload,
            timeout=self.timeout_seconds,
        )
        return self._decode_response(response)

    @staticmethod
    def _decode_response(response: requests.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError:
            response.raise_for_status()
            raise

        if response.status_code >= 400:
            raise requests.HTTPError(
                f"{response.status_code} {response.reason}: {json.dumps(body, ensure_ascii=False)}",
                response=response,
            )

        return body

    @staticmethod
    def _to_token_pair(data: dict[str, Any]) -> TokenPair:
        return TokenPair(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=int(data.get("expires_in", 0)),
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Auth Service example client")
    parser.add_argument("--base-url", default="https://example", help="Auth service URL")
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID")
    parser.add_argument("--email", required=True, help="User email")
    parser.add_argument("--password", required=True, help="User password")
    parser.add_argument("--audience", default="auth-service", help="JWT audience")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = AuthClient(base_url=args.base_url)

    try:
        print("[1/4] Login...")
        login_tokens = client.login(args.tenant_id, args.email, args.password, args.audience)
        print(f"Login success. Access expires in: {login_tokens.expires_in}s")

        print("[2/4] Userinfo...")
        me = client.userinfo(login_tokens.access_token, args.audience)
        print("Userinfo:", json.dumps(me, ensure_ascii=False, indent=2))

        print("[3/4] Refresh token...")
        refreshed = client.refresh(login_tokens.refresh_token, args.audience)
        print(f"Refresh success. New access expires in: {refreshed.expires_in}s")

        print("[4/4] Logout (revoke refresh)...")
        logout_result = client.logout(refreshed.refresh_token)
        print("Logout:", json.dumps(logout_result, ensure_ascii=False))

    except requests.HTTPError as exc:
        print(f"HTTP error: {exc}", file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
