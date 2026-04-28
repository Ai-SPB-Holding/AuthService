# Rust iframe demo (Axum)

Embedded-login demo aligned with [`examples/python/README_iframe_demo.md`](../../python/README_iframe_demo.md): Axum BFF, SQLite token store, iframe + `postMessage`, `/auth/callback`, profile with live `userinfo` via **`authservice-sdk`**.

## Differences vs Python

| Topic | Python | Rust |
|--------|--------|------|
| OIDC refresh button | `POST /demo/oidc-refresh` (no body) | `GET /demo/oidc-refresh` (same UX from `fetch`; avoids Axum type-inference quirks with `Result<(StatusCode, Json), …>` on that route) |
| SQLite file default | `iframe_demo.sqlite3` | `iframe_demo_rust.sqlite3` |

## Prerequisites

Same as the Python README: Auth Service running, Redis/Postgres, OAuth clients with embedded login + parent origins, etc.

## Env

Copy [`examples/python/.env.iframe.example`](../../python/.env.iframe.example) or use [`.env.example`](.env.example), then export variables (same names as Python for `CLIENT_*`, `TENANT_ID`, `AUTH_*`).

Extra for the Rust SDK:

- **`REDIRECT_URL`** — registered redirect URI for your OAuth client (defaults to `http://127.0.0.1:<port>/oauth/callback` if unset). Required by `authservice-sdk` config validation even though this iframe demo does not use the authorization-code redirect flow.

## Run

From repository root:

```bash
export $(grep -v '^#' examples/rust/iframe_demo/.env.example | xargs)  # after editing values
cargo run -p iframe-demo --bin iframe-client-9999   # confidential, default port 9999
cargo run -p iframe-demo --bin iframe-client-9898   # public, default port 9898
```

Open `http://127.0.0.1:9999` or `:9898` as configured.

## Layout

- `src/` — Axum app, SQLite store (same schema as Python `iframe_demo_common/store.py`)
- `templates/` — HTML (placeholder substitution)
- `static/embedded-auth-sdk-demo.js` — same adapter idea as the Python static file
