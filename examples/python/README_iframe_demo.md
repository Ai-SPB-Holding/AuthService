# Iframe login demo (Python)

Two minimal **client applications** that embed Auth Service login in an `<iframe>` and store tokens in **SQLite**.

| Port  | OAuth type     | Script                          |
|-------|----------------|---------------------------------|
| 9999  | Confidential   | `iframe_client_9999_confidential.py` |
| 9898  | Public         | `iframe_client_9898_public.py`   |

## Prerequisites

1. Auth Service running (e.g. `http://127.0.0.1:8080`).
2. Redis + Postgres migrated (including `0009_embedded_login.sql`).
3. Two OAuth clients created in the admin dashboard with:
   - **9999**: type **confidential** — save the **client secret** once.
   - **9898**: type **public**.
4. For **each** client, enable **Embedded iframe login** and set **Parent origins** to include:
   - The **page that embeds the iframe** (your Flask demo), e.g. **`http://localhost:9999` AND `http://127.0.0.1:9999`** — add both if you might open either hostname. This is what the browser sends as `Referer`/`Origin`; it is **not** the same as the Auth UI URL.
   - The **Auth Service UI** origin: `http://localhost:8080` (and `http://127.0.0.1:8080` if you use it) — needed for CSP `frame-ancestors`.
   - Same for port **9898** if you use the public demo.

   Use **exact** origins (scheme + host + port). Wildcards like `https://*.example.com` are supported by the auth service validator if you prefer.

   **Docker:** Auth in Docker + demo on the host is fine; still list `http://localhost:9999` (etc.) as parent origins — the browser’s Referer is the host machine URL, not a container hostname.

5. `AUTH_PUBLIC_ORIGIN` in your env must match **exactly** what the browser uses for the auth service (the iframe `postMessage` origin). Example: `http://localhost:8080`.

6. `AUTH_API_BASE` should be reachable from Python (`http://127.0.0.1:8080` is a good default).

## Install

```bash
cd examples/python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.iframe.example .env.iframe
# Edit .env.iframe: TENANT_ID, CLIENT_9898_ID, CLIENT_9999_ID, CLIENT_9999_SECRET
set -a; source .env.iframe; set +a
```

## Run

Terminal 1 — confidential demo:

```bash
cd examples/python
source .venv/bin/activate
set -a; source .env.iframe; set +a
python iframe_client_9999_confidential.py
```

Terminal 2 — public demo:

```bash
cd examples/python
source .venv/bin/activate
set -a; source .env.iframe; set +a
python iframe_client_9898_public.py
```

Open:

- `http://127.0.0.1:9999` — login iframe + **OIDC refresh** button (uses `client_secret`).
- `http://127.0.0.1:9898` — login iframe only.

On the login page, the demo now uses a small browser SDK adapter and shows two buttons:
- **Server default theme**
- **Client custom theme**

They send `THEME_UPDATE` to the iframe (`postMessage` v2). For this to work, enable **Embedded protocol v2** on the OAuth client in the admin UI.

## Flow

1. **Register (end users)** — Use the iframe **Register** tab: `GET /embedded-login?client_id=…` and `POST /api/register` (+ email verify / optional client TOTP) when the OAuth client has **Allow user registration** and **Embedded iframe login**. This is the only supported path for unauthenticated public registration.
2. **Register (automation / admin)** — `POST /auth/register` with a valid **admin** Bearer JWT (`AUTH__ADMIN_API_AUDIENCE` + `admin` role), or `POST /admin/users` with the same. **Do not** call `POST /auth/register` without that token; it returns 401/403.
3. **Local demo “Register” page** — `http://127.0.0.1:9999/register` is a **negative test**: it calls `POST /auth/register` without a token; the API rejects it (expected). Use the iframe for real sign-up.
4. **Login** — iframe loads `GET {AUTH_PUBLIC_ORIGIN}/embedded-login?client_id=...`, then `postMessage` returns an **access_token** (the Auth Service does **not** put `refresh_token` in iframe responses; use a BFF or confidential `/oauth2/token` for refresh).
5. **Callback** — browser `fetch` to local `/auth/callback`; server calls `GET /userinfo` and stores tokens in `SQLITE_PATH`.
6. **Profile** — shows live `userinfo` JSON from Auth Service.

### Troubleshooting

- **Iframe shows “Signed in” but Profile is empty / you stay on login:** the parent page never accepted `AUTH_SUCCESS`. Common causes: (1) old demo JS required `refresh_token` in `postMessage` — update this repo’s `embedded-auth-sdk-demo.js` / `index.html`; (2) **`JWT_AUDIENCE_*` must match** the client’s embedded token audience in admin (often equals `client_id`); wrong values make `/userinfo` fail after redirect; (3) **localhost vs 127.0.0.1** for `AUTH_PUBLIC_ORIGIN` vs the URL the iframe actually loads — the demo allowlists both loopback hostnames for `postMessage` origins.
7. **Refresh tokens** (page button on port **9999**) — `POST {AUTH_API_BASE}/token` with `grant_type=refresh_token` and the stored refresh token. The Auth Service **aud** for the new access/refresh pair is read from the refresh JWT itself (it must match the audience you used at login, e.g. the OAuth client’s `embedded_token_audience` or `client_id`); a wrong `JWT_AUDIENCE_9999` in `.env` no longer causes 401. Optional `client_id` / `client_secret` in the body are fine for a confidential client demo; they are not what validates the refresh today (401 was almost always an audience mismatch before this fix).

## SQLite

Default file: `examples/python/iframe_demo.sqlite3` (gitignored). Tables: `demo_sessions`, `demo_tokens` keyed by `(client_label, session_id)`.

## Troubleshooting

- **Plain “Not found” on `/embedded-login`**: in current Auth Service builds you instead get a clearer page:
  - **Unknown OAuth client_id** — typo or wrong environment; check the admin **Clients** list.
  - **Embedded iframe login is disabled** — open the client in the dashboard, enable **Embedded iframe login**, set **Parent origins**, save. The admin **OAuth clients** form includes a copy-paste **iframe HTML** snippet.
- **Iframe blank / CSP blocked**: add missing parent origins (including `http://localhost:8080` vs `http://127.0.0.1:8080` — pick one and be consistent).
- **postMessage ignored**: `AUTH_PUBLIC_ORIGIN` must equal `event.origin` from the auth page.
- **“Referer/Origin check failed”** (403 on `/embedded-login`): the OAuth client’s **Parent origins** must include the **demo app** origin (`http://localhost:9999` or `http://127.0.0.1:9999`), not only `http://localhost:8080`. Use the same hostname in the browser as in the list. For a quick local bypass, set `AUTH__EMBEDDED_RELAX_PARENT_ORIGIN_CHECK=true` on the Auth Service (dev only).
- **`Auth error: CSRF_INVALID` / missing csrf cookie** on Register or Login in the iframe: usually **localhost vs 127.0.0.1** — the parent was `http://127.0.0.1:9999` while `AUTH_PUBLIC_ORIGIN` was `http://localhost:8080`, so the iframe was cross-site and the browser did not keep `embedded_csrf`. The demo now picks `http://127.0.0.1:8080` when you open the app on `127.0.0.1`. Alternatively open the demo at `http://localhost:9999` everywhere.
- **401 on OIDC `POST /token` (`grant_type=refresh_token`)** — see **Flow** step 7: audience for rotation comes from the refresh token, not your env `JWT_AUDIENCE_9999`. Other causes: wrong refresh token, reuse after rotation, logout, or missing Redis/DB for the session.
