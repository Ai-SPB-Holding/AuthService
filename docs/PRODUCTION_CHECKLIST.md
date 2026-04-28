# Production checklist — AuthService

## Secrets and keys
- [ ] No secrets or `.pem` files in the repository; use Vault / cloud secret manager
- [ ] `AUTH__JWT_*` and `AUTH__COOKIE_SECRET` (≥32 bytes) from secure generation
- [ ] `TOTP__ENCRYPTION_KEY_B64` decodes to 32 bytes; stored in HSM/secret store
- [ ] `CORS__ALLOWED_ORIGINS` set to real dashboard/admin origins (comma-separated)
- [ ] `AUTH__ADMIN_API_AUDIENCE` matches dashboard `VITE_DEFAULT_AUDIENCE`
- [ ] Optional: `METRICS__BYPASS_TOKEN` and require `Authorization: Bearer` on `/metrics`
- [ ] `OIDC__LOGIN_URL` set for browser `GET /authorize` flow when not using API-only
- [ ] `OIDC__CLIENT_MFA_ENFORCE` aligned with rollout (default `true`: per-client TOTP required on login/OIDC when client policy is `required`)

## Database
- [ ] Migrations `0001`–`0010` applied in order (`0006` per-client MFA; `0007` user `registration_source`; `0010` embedded pending registration when client MFA is `required`)
- [ ] Backups and tested restore
- [ ] No plaintext OAuth client secrets in DB (use `client_secret_argon2`; rotate old clients)

## OAuth / OIDC
- [ ] `.well-known/openid-configuration` matches deployed URLs (issuer, endpoints)
- [ ] `GET /authorize` tested with PKCE and redirect to `allowed_redirect_uris` only
- [ ] `POST /token` `authorization_code` and `refresh_token` grants tested; rotation verified
- [ ] Identity: `id_token` when `openid` in scope; `userinfo` with Bearer

## Hardening
- [ ] Rate limits and WAF in front of `/auth/*`, `/token`
- [ ] TLS termination with HSTS at edge
- [ ] Structured logs (JSON) + log aggregation; no PII in `error` JSON bodies
- [ ] Alerts: auth failure spikes, refresh reuse, DB/RDS errors

## UI (dashboard)
- [ ] `VITE_API_BASE_URL` and `VITE_DEFAULT_AUDIENCE` point to production
- [ ] `VITE_ENV_NAME=production` (or `staging`) for login banner
- [ ] Nginx/edge: TLS, optional CSP, frame deny

## Embedded iframe (`/embedded-login`)
- [ ] Client has `embedded_login_enabled`, parent origins, and registration flags as intended
- [ ] **`mfa_policy = required` + `allow_client_totp_enrollment = true`**: new registration does not create a `users` row until email code **and** client TOTP verify; response includes `registration_mode: pending_mfa_required` then enrollment JWT after email verify
- [ ] **`mfa_policy = required` + `allow_client_totp_enrollment = false`**: `POST /api/register` returns `MFA_ENROLLMENT_DISABLED` (configure client before rollout)
- [ ] **`mfa_policy` optional/off**: registration stays email-verify → tokens (no mandatory client TOTP setup in iframe)
- [ ] Login for existing users with `required`: password step then client TOTP step-up as before
- [ ] Negative paths: wrong email code, expired pending row, invalid enrollment JWT, resend-code for pending vs existing user

## Runbooks
- [ ] Key rotation: add JWKS `kid`, deploy, wait for max access TTL, remove old `kid`
- [ ] Client secret rotation: create new, update RPs, revoke old
- [ ] Incident: global refresh revoke SQL / admin tooling documented

## Load and chaos
- [ ] Sustained load on `/token` and `/auth/login`
- [ ] Redis/Postgres failure modes (degraded / fail closed)

See also [SECRETS_AND_KEYS.md](SECRETS_AND_KEYS.md).
