# DAST / smoke targets (AuthService)

Used by `test/scripts/run-zap-baseline.sh`, `run-headers-check.sh`, and docs.

## External (host → published ports)

| Role | URL | Notes |
|------|-----|--------|
| Backend direct | `http://127.0.0.1:8080` | Same routes as in `backend/src/lib.rs` |
| Dashboard (nginx) | `http://127.0.0.1:5173` | Proxies `/api/` → `backend:8080/` |

## Unauthenticated GET smoke (safe for scanners)

- `GET /health` — liveness
- `GET /.well-known/openid-configuration` — OIDC metadata
- `GET /.well-known/jwks.json` — JWKS
- `GET /embedded-login` — embedded UI page (may require client query params in practice)

## Authenticated flows

Admin, token, and embedded flows require credentials or client configuration; **not** included in default ZAP baseline. Extend `test/config/zap-baseline-rules.tsv` / custom scripts when you have a disposable test tenant.

## Internal (inside `backend` container)

- `GET http://127.0.0.1:8080/health` — `docker compose exec backend wget -qO- …`
