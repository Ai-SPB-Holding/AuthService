from __future__ import annotations

import json
from typing import Any

import requests


class AuthServiceClient:
    def __init__(self, base_url: str, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def register(
        self,
        tenant_id: str,
        email: str,
        password: str,
        registration_source: str | None,
    ) -> dict[str, Any]:
        """POST /auth/register — **admin API tokens only** (Bearer + admin audience + admin role).

        End-user self-registration uses the embedded iframe flow: ``/embedded-login`` and
        ``POST /api/register*``. This method remains for integration tests and the demo's
        intentional negative test at ``/register``.
        """
        payload: dict[str, Any] = {
            "tenant_id": tenant_id,
            "email": email,
            "password": password,
        }
        if registration_source:
            payload["registration_source"] = registration_source
        return self._post_json("/auth/register", payload)

    def userinfo(self, access_token: str) -> dict[str, Any]:
        r = self.session.get(
            f"{self.base_url}/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=self.timeout,
        )
        return self._decode(r)

    def refresh_oidc(
        self,
        refresh_token: str,
        audience: str,
        client_id: str,
        client_secret: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "audience": audience,
            "client_id": client_id,
        }
        if client_secret:
            payload["client_secret"] = client_secret
        return self._post_json("/token", payload)

    def logout(self, refresh_token: str) -> dict[str, Any]:
        return self._post_json("/auth/logout", {"refresh_token": refresh_token})

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        r = self.session.post(
            f"{self.base_url}{path}",
            json=payload,
            timeout=self.timeout,
        )
        return self._decode(r)

    def _decode(self, r: requests.Response) -> dict[str, Any]:
        try:
            body = r.json()
        except ValueError:
            r.raise_for_status()
            raise
        if r.status_code >= 400:
            raise requests.HTTPError(
                f"{r.status_code} {r.reason}: {json.dumps(body, ensure_ascii=False)}",
                response=r,
            )
        return body
