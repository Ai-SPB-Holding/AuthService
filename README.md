# Auth Service (Rust)

Production-oriented Auth/IAM service with Axum + SQLx + Redis and OIDC-compatible endpoints.

## Architecture

- `auth-service` is stateless for access path (JWT RS256).
- PostgreSQL stores identity, RBAC, OAuth artifacts.
- Redis stores shared runtime state: rate limits, replay protection, token revocation.
- Supports local auth and OIDC proxy mode (`OIDC__SERVER_METADATA_URL`).
- Multi-tenant by explicit `tenant_id` across user/client/role/auth tables and claims.

## Docs

- [Secrets, keys, rotation](docs/SECRETS_AND_KEYS.md)
- [Production checklist](docs/PRODUCTION_CHECKLIST.md)
- [Embedded iframe postMessage protocol (v2)](docs/EMBEDDED_IFRAME_PROTOCOL.md)

## Examples

- Python CLI: [examples/python/auth_via_example.py](examples/python/auth_via_example.py)
- Local **iframe login** demos (Flask + SQLite): [examples/python/README_iframe_demo.md](examples/python/README_iframe_demo.md)

## Implemented API

- OIDC:
  - `GET /.well-known/openid-configuration`
  - `GET /authorize` (legacy JSON-oriented stack; Authorization Code + PKCE; `idp_session` cookie or `OIDC__LOGIN_URL` redirect)
  - `POST /token` (JSON body; grants: `authorization_code`, `refresh_token`; `password` only if `AUTH__ALLOW_RESOURCE_OWNER_PASSWORD_GRANT=true`)
  - **RFC-style OAuth2** (form-encoded `application/x-www-form-urlencoded`): `GET /oauth2/authorize`, `POST /oauth2/token` (includes `embedded_session` for iframe→BFF exchange), `GET /oauth2/userinfo`, `POST /oauth2/introspect`, `POST /oauth2/revoke`
  - `GET /userinfo` (Bearer; `aud` must be admin audience or a registered OAuth client)
  - `GET /jwks.json` (RSA `n`/`e` for verifiers)
  - `POST /revoke` / `POST /introspect` — require `client_id` (+ `client_secret` for confidential clients); supports `Authorization: Basic`
- Auth:
  - `POST /auth/register` — **admin API only**: `Authorization: Bearer` JWT with `aud` = `AUTH__ADMIN_API_AUDIENCE` and `admin` role. Public self-registration: embedded flow below (`/api/register*`)
  - `POST /auth/login`
  - `POST /auth/refresh`
  - `POST /auth/logout`
- Admin (create endpoints):
  - `POST /admin/clients`
  - `POST /admin/users`
  - `POST /admin/roles`
- Embedded iframe (`GET /embedded-login?client_id=…` when client has `embedded_login_enabled` + parent origins):
  - `POST /api/login` — password login (+ CSRF cookie); returns **access_token only** to the iframe (no `refresh_token` in JSON / postMessage)
  - `POST /api/session-code` — from iframe `access_token`, mint a one-time code for BFF exchange (`grant_type=embedded_session` on `POST /oauth2/token`)
  - `POST /api/register` — start registration when `allow_user_registration`; returns `email_verification` JWT
  - `POST /api/register/verify-email` — 6-digit code + verification JWT; returns access/refresh (`aud` = embedded audience or client id)
  - `POST /api/register/resend-code` — new verification JWT (same CSRF session)
- Dashboard / settings (Bearer + admin audience):
  - `GET /admin/session` — `is_admin`, `is_client_settings_member` (row in `client_user_membership`)
  - `GET /admin/settings` — effective flags and masked secret presence (reads merged `.env` + process config)
  - `PUT /admin/settings` — updates canonical keys in `AUTH__ENV_FILE_PATH` (default `.env`); restart required

## Security

- Argon2 password hashing; OAuth **client** secrets stored as Argon2 hashes
- RS256 access / refresh / ID token; `jti` on access; refresh rotation + family reuse detection
- Admin API requires `aud` = `AUTH__ADMIN_API_AUDIENCE` (e.g. `auth-service`)
- PKCE S256; per-client `allowed_redirect_uris`; authorization codes are one-time; refresh tokens can be bound to OAuth `client_id` so confidential clients must re-authenticate on refresh
- CORS from `CORS__ALLOWED_ORIGINS` (empty = no cross-origin CORS)
- Brute force/rate controls with Redis; MFA step-up JTI one-time
- Optional `METRICS__BYPASS_TOKEN` for `/metrics`
- Structured logging + `/metrics` (Prometheus)

## Required env vars (minimal)

- `AUTH__JWT_PRIVATE_KEY_PEM` / `AUTH__JWT_PUBLIC_KEY_PEM` (RSA, PEM; see [SECRETS_AND_KEYS](docs/SECRETS_AND_KEYS.md))
- `AUTH__COOKIE_SECRET` (≥32 chars) for `idp_session` and MFA Redis-backed step-up
- `AUTH__ADMIN_API_AUDIENCE` — must match dashboard `VITE_DEFAULT_AUDIENCE`
- `DATABASE__URL`, `REDIS__URL`, `SERVER__ISSUER`
- `CORS__ALLOWED_ORIGINS` (comma-separated) for the dashboard origin in dev/prod
- `OIDC__KEYCLOAK_*`, `OIDC__REDIRECT_URL` (legacy/integrations), `OIDC__SERVER_METADATA_URL` (optional proxy)
- `OIDC__LOGIN_URL` (optional) for unauthenticated browser `/authorize`
- Optional: `METRICS__BYPASS_TOKEN` to protect `/metrics`
- Dashboard: `VITE_SET_IDP_SESSION=true` + `AUTH__COOKIE_SECRET` to receive `idp_session` for `/authorize` in the same browser

## Run

1. Copy `.env.example` to `.env` and fill real keys.
2. Start dependencies:
   - `docker compose up -d postgres redis`
3. Apply SQL migrations in order (`backend/migrations/0001_init.sql` through `0014_embedded_session_exchange.sql`). Example:

   `docker compose exec -T postgres psql -U auth -d auth < backend/migrations/0001_init.sql`
4. Start service:
   - `cargo run`

## Docker

- `docker compose up --build`

## Dashboard Settings & client delegates

- Admins (`admin` role) have full UI access; OAuth client delegates need a row in `client_user_membership` (`tenant_id`, `user_id`, `client_id` → `clients.id`). They only see the **Settings** tab but may update the same `.env` keys (policy toggles are server-enforced for admins only).
- Sensitive changes (issuer URL, JWT PEMs, cookie secret, TOTP encryption key) require a valid **Google Authenticator** code when `AUTH__REQUIRE_LOGIN_2FA` is true or the acting user has TOTP enabled.

### Service-wide admin (all tenants in dashboard)

- By default, `/admin/*` is scoped to the **`tenant_id` in the JWT** (the tenant you used at login). A new user from `make user-add` is in a **new** tenant, so the dashboard only shows that org until you add more users there.
- Set **`AUTH__GLOBAL_ADMIN_USER_IDS`** to a comma-separated list of **user UUIDs** (from `users.id`) for accounts that should see **all tenants**: aggregate dashboard metrics, list all users/clients/sessions, RBAC with optional `tenant_id` on each row, etc. Restart the API after changing `.env`.
- Example: add your first operator’s `id` (from `make user-list`) and keep logging in with that user to manage the whole deployment.
