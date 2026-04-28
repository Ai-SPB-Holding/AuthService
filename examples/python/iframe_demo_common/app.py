from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
import requests

from iframe_demo_common.auth_backend import AuthServiceClient
from iframe_demo_common.settings import DemoSettings
from iframe_demo_common.store import SqliteTokenStore

SESSION_KEY = "iframe_demo_sid"


def browser_auth_origin(req, settings: DemoSettings) -> str:
    """Use the same hostname as the parent page for the auth iframe URL.

    If the demo is opened at ``http://127.0.0.1:9999`` but ``AUTH_PUBLIC_ORIGIN`` is
    ``http://localhost:8080``, the iframe becomes cross-site and browsers often block
    ``SameSite=Lax`` CSRF cookies set inside the iframe — ``POST /api/register`` then
    fails with ``CSRF_INVALID`` / missing cookie. Matching hostnames avoids that.
    """
    cfg = urlparse(settings.auth_public_origin)
    parent_host = (req.host or "").split(":", 1)[0].lower()
    if cfg.hostname in ("localhost", "127.0.0.1") and parent_host in (
        "localhost",
        "127.0.0.1",
    ):
        port = cfg.port or (443 if cfg.scheme == "https" else 80)
        netloc = f"{parent_host}:{port}"
        return urlunparse((cfg.scheme, netloc, "", "", "", "")).rstrip("/")
    return settings.auth_public_origin.rstrip("/")


def create_app(settings: DemoSettings) -> Flask:
    root = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(root / "templates"),
    )
    app.secret_key = settings.flask_secret
    store = SqliteTokenStore(settings.sqlite_path)
    auth = AuthServiceClient(settings.auth_api_base)

    def client_session_id() -> str:
        sid = session.get(SESSION_KEY)
        sid = store.ensure_session(sid, settings.client_label)
        session[SESSION_KEY] = sid
        session.permanent = True
        return sid

    @app.route("/")
    def index():
        iframe_origin = browser_auth_origin(request, settings)
        return render_template(
            "index.html",
            settings=settings,
            iframe_origin=iframe_origin,
            iframe_src=f"{iframe_origin}/embedded-login?client_id={settings.oauth_client_id}",
        )

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html", settings=settings)
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if len(password) < 10:
            return (
                render_template(
                    "register.html",
                    settings=settings,
                    error="Password must be at least 10 characters (Auth Service rule).",
                ),
                400,
            )
        try:
            out = auth.register(
                settings.tenant_id,
                email,
                password,
                registration_source=settings.oauth_client_id,
            )
        except requests.HTTPError as e:
            msg = str(e)
            status = 400
            if e.response is not None:
                try:
                    msg = e.response.json().get("error", msg)
                except Exception:
                    pass
                sc = e.response.status_code
                if sc in (401, 403):
                    status = sc
            return (
                render_template("register.html", settings=settings, error=msg),
                status,
            )
        return render_template(
            "register_done.html",
            settings=settings,
            register_json_pretty=json.dumps(out, indent=2, ensure_ascii=False),
        )

    @app.route("/auth/callback", methods=["POST"])
    def auth_callback():
        sid = client_session_id()
        data = request.get_json(force=True, silent=False)
        access = data.get("access_token")
        refresh = data.get("refresh_token") or ""
        if not access:
            return jsonify({"ok": False, "error": "missing access_token"}), 400
        email = None
        sub = None
        try:
            info = auth.userinfo(access)
            email = info.get("email")
            sub = info.get("sub")
        except requests.HTTPError:
            pass
        store.save_tokens(
            sid,
            settings.client_label,
            email,
            sub,
            access,
            refresh if isinstance(refresh, str) else "",
        )
        return jsonify({"ok": True, "redirect": url_for("profile")})

    @app.route("/profile")
    def profile():
        sid = client_session_id()
        rec = store.get_tokens(sid, settings.client_label)
        if rec is None:
            return redirect(url_for("index"))
        try:
            info = auth.userinfo(rec.access_token)
        except requests.HTTPError:
            info = None
        return render_template(
            "profile.html",
            settings=settings,
            userinfo=info,
            record=rec,
            raw_stored={
                "access_token_prefix": rec.access_token[:24] + "…",
                "refresh_token_prefix": rec.refresh_token[:24] + "…",
            },
        )

    @app.route("/demo/oidc-refresh", methods=["POST"])
    def oidc_refresh():
        if not settings.is_confidential or not settings.oauth_client_secret:
            return jsonify({"ok": False, "error": "only for confidential client with secret"}), 400
        sid = client_session_id()
        rec = store.get_tokens(sid, settings.client_label)
        if rec is None:
            return jsonify({"ok": False, "error": "no session"}), 400
        try:
            out = auth.refresh_oidc(
                rec.refresh_token,
                settings.jwt_audience,
                settings.oauth_client_id,
                settings.oauth_client_secret,
            )
        except requests.HTTPError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        access = out.get("access_token")
        refresh = out.get("refresh_token", rec.refresh_token)
        if not access:
            return jsonify({"ok": False, "error": "no access_token in token response", "body": out}), 400
        try:
            info = auth.userinfo(access)
        except requests.HTTPError:
            info = None
        store.save_tokens(
            sid,
            settings.client_label,
            rec.email,
            rec.sub,
            access,
            refresh,
        )
        return jsonify({"ok": True, "userinfo": info})

    @app.route("/logout", methods=["POST"])
    def logout():
        sid = session.get(SESSION_KEY)
        if sid:
            rec = store.get_tokens(sid, settings.client_label)
            if rec:
                if rec.refresh_token:
                    try:
                        auth.logout(rec.refresh_token)
                    except requests.HTTPError:
                        pass
                store.clear_tokens(sid, settings.client_label)
        session.pop(SESSION_KEY, None)
        return redirect(url_for("index"))

    @app.route("/admin/tokens")
    def admin_tokens():
        """Debug: list recent token rows for this client (no secrets)."""
        rows = store.list_for_client(settings.client_label)
        return jsonify({"client": settings.client_label, "rows": rows})

    return app


def run_demo(settings: DemoSettings) -> None:
    app = create_app(settings)
    # noqa: Werkzeug serving is intentional for local demos
    app.run(
        host=os.environ.get("DEMO_BIND", "127.0.0.1"),
        port=settings.listen_port,
        debug=os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes"),
    )
