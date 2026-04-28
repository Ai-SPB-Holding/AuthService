from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return v.strip()


@dataclass(frozen=True)
class DemoSettings:
    """Runtime config for one demo client process."""

    client_label: str
    listen_port: int
    auth_public_origin: str
    auth_api_base: str
    oauth_client_id: str
    oauth_client_secret: str | None
    tenant_id: str
    jwt_audience: str
    sqlite_path: str
    flask_secret: str
    is_confidential: bool

    @staticmethod
    def load_confidential_9999() -> "DemoSettings":
        public = _env("AUTH_PUBLIC_ORIGIN", "http://localhost:8080")
        internal = _env("AUTH_API_BASE", "http://127.0.0.1:8080")
        cid = _env("CLIENT_9999_ID")
        secret = _env("CLIENT_9999_SECRET")
        tid = _env("TENANT_ID")
        if not cid or not secret or not tid:
            raise SystemExit(
                "Set CLIENT_9999_ID, CLIENT_9999_SECRET, TENANT_ID (see .env.iframe.example)"
            )
        aud = _env("JWT_AUDIENCE_9999", cid)
        return DemoSettings(
            client_label="confidential @ :9999",
            listen_port=int(_env("DEMO_PORT_9999", "9999")),
            auth_public_origin=public.rstrip("/"),
            auth_api_base=internal.rstrip("/"),
            oauth_client_id=cid,
            oauth_client_secret=secret,
            tenant_id=tid,
            jwt_audience=aud,
            sqlite_path=_env("SQLITE_PATH", "iframe_demo.sqlite3"),
            flask_secret=_env("FLASK_SECRET_KEY", "dev-change-me-iframe-demo"),
            is_confidential=True,
        )

    @staticmethod
    def load_public_9898() -> "DemoSettings":
        public = _env("AUTH_PUBLIC_ORIGIN", "http://localhost:8080")
        internal = _env("AUTH_API_BASE", "http://127.0.0.1:8080")
        cid = _env("CLIENT_9898_ID")
        tid = _env("TENANT_ID")
        if not cid or not tid:
            raise SystemExit("Set CLIENT_9898_ID, TENANT_ID (see .env.iframe.example)")
        aud = _env("JWT_AUDIENCE_9898", cid)
        return DemoSettings(
            client_label="public @ :9898",
            listen_port=int(_env("DEMO_PORT_9898", "9898")),
            auth_public_origin=public.rstrip("/"),
            auth_api_base=internal.rstrip("/"),
            oauth_client_id=cid,
            oauth_client_secret=None,
            tenant_id=tid,
            jwt_audience=aud,
            sqlite_path=_env("SQLITE_PATH", "iframe_demo.sqlite3"),
            flask_secret=_env("FLASK_SECRET_KEY", "dev-change-me-iframe-demo"),
            is_confidential=False,
        )
