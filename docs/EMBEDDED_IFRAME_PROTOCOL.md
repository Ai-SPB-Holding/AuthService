# Embedded iframe postMessage protocol (v2)

This document describes the **optional** v2 message protocol for communication between the hosted Auth Service `/embedded-login` page (iframe) and the **parent** application. When `embedded_protocol_v2` is **disabled** for the OAuth client, the iframe only sends **legacy** messages without `v`, `ts`, or `nonce` (see [Legacy](#legacy-behavior-when-embedded_protocol_v2--false)).

## Security invariants (both modes)

- The **parent** MUST verify `MessageEvent.origin` against the same allowlist as configured on the client (`embedded_parent_origins`) plus the IdP origin when applicable.
- The parent MUST require `event.source === iframe.contentWindow` when handling `postMessage`.
- The iframe validates incoming parent messages: `event.origin` must be one of the client’s `embedded_parent_origins` (or the resolved parent origin the server used for the page load). Unknown origins are ignored.

## Envelope (v2 only)

All v2 messages are JSON objects with at least:

| Field   | Type   | Required | Description |
|---------|--------|----------|-------------|
| `v`     | number | yes      | Protocol version, currently `1` |
| `type`  | string | yes      | Message type (see table below) |
| `ts`    | number | yes      | Unix time in seconds (integer) |
| `source`| string | yes      | `auth_iframe` or `parent_sdk` |
| `nonce` | string | yes    | Non-empty; UUID is recommended |

Additional fields are type-specific. Implementations SHOULD reject unknown `v` for forward compatibility (only `1` is defined today).

## Message types

| `type`          | Direction        | Description |
|-----------------|------------------|-------------|
| `EMBED_READY`   | iframe → parent  | Iframe script loaded; CFG is available. Not a security proof; follow with `INIT` from the parent. |
| `INIT`          | parent → iframe  | Optional handshake. Parent may send `parent_origin` (string); iframe compares with `MessageEvent.origin`. |
| `INIT_ACK`      | iframe → parent  | `allowed` (boolean), `client_id` (string), `protocol_version` (number). If `allowed` is false, do not expect token messages. |
| `THEME_UPDATE`  | parent → iframe  | `theme` object (see [Theme object](#theme-object-embedded_ui_theme--runtime)); merged at runtime. |
| `LOGOUT`        | parent → iframe  | UIO only: ask iframe to clear visible forms; server refresh revocation remains `POST /auth/logout` with the refresh token on the **parent** or BFF. |
| `SESSION_ENDED` | iframe → parent  | Optional notice after `LOGOUT` handling in iframe. |
| `AUTH_SUCCESS`  | iframe → parent  | **BFF (recommended):** `code`, `token_type` (`embedded_session`), `expires_in` for the one-time code (minted server-side after login; parent exchanges via `POST /oauth2/token` with `grant_type=embedded_session`). **Legacy:** `access_token`, optional `refresh_token` (may be omitted). Envelope + fields. |
| `AUTH_ERROR`    | iframe → parent  | `error` (machine code), `message` (human-readable). Envelope + error fields. |

## Handshake (recommended, v2)

1. Iframe dispatches `EMBED_READY` with a fresh `nonce_iframe` (also in the envelope as `nonce`).  
   **Note:** In strict browsers (Safari / third‑party cookie blocking), the iframe may show an **“Allow cookies”** step first and only send `EMBED_READY` after the HttpOnly CSRF cookie is available (`GET /api/embedded/csrf-check` returns 204), possibly after `document.requestStorageAccess()`.
2. Parent sends `INIT` with a new `nonce` and, if desired, `parent_origin: window.location.origin`.
3. Iframe responds with `INIT_ACK` with `allowed: true` if `event.origin` is in the allowlist, else `allowed: false`.

The iframe will still complete login; `INIT` is for SDK alignment and gating of optional behavior.

## return_to and new-tab sign-in

Optional query parameter on `GET /embedded-login`:

`return_to=<absolute-URL>`

- The URL must use `http` or `https`, must not include userinfo, and its **origin** must match one of the client’s `embedded_parent_origins` patterns (same rules as parent origin checks).
- The Auth Service injects it into the page `CFG` as `return_to` when valid; invalid values are ignored.
- After a successful BFF session-code mint, if `CFG.return_to` is set, the browser is sent to  
  `return_to#embedded_session_code=<one_time_code>`  
  then `window.close()` is attempted (works when the tab was opened via `window.open`; harmless otherwise).
- The host SPA should read the hash, call its BFF `POST .../embedded/exchange` with `code`, then strip the hash with `history.replaceState`.
- `@auth-service/embedded-auth`: pass `returnTo` in options; `load()` sends it as the `return_to` query param.

## Theme object (`embedded_ui_theme` + runtime)

**Theme** is a restricted JSON object. Never includes raw CSS, URLs, or script.

Allowed top-level keys (v1 theme schema, version in `v` under theme, same as protocol `v=1` for theme sub-object):

| Key           | Type   | Constraints |
|---------------|--------|-------------|
| `v`           | number | Must be `1` |
| `colorScheme` | string | `light` \| `dark` \| `system` |
| `colors`      | object | Map of `primary` \| `onPrimary` \| `background` \| `surface` \| `error` → color string (see [Color string](#color-string)) |
| `radius`      | object | Keys `sm` \| `md` \| `lg` (optional); value 0–24 (integer, **pixels**). |
| `spacing`     | object | Keys `sm` \| `md` \| `lg` (optional); 0–32 (integer, **pixels**). |
| `font`        | object | `family`: `system` \| `serif` \| `mono`; `size`: `sm` \| `md` \| `lg` |

The Auth Service **validates and stores** `embedded_ui_theme` on the client. Runtime `THEME_UPDATE` must pass the same validation rules; invalid updates are ignored.

### Color string

- `#RGB`, `#RRGGBB`, or `#RRGGBBAA` (hex, case-insensitive)
- or `rgb(...)` / `hsl(...)` with numbers only, max length 64

**Rejected:** any substring `url(`, `expression(`, `javascript:`, `<`, `import` (case-insensitive).

## Legacy behavior (`embedded_protocol_v2 == false`)

The iframe posts:

- Success (BFF): `{ "type": "AUTH_SUCCESS", "code": "...", "token_type": "embedded_session", "expires_in": 120 }`
- Success (legacy): `{ "type": "AUTH_SUCCESS", "access_token": "...", "refresh_token": "..." }`
- Error: `{ "type": "AUTH_ERROR", "error": "CODE", "message": "..." }`

No `v` / `ts` / `nonce` / `source` fields. Parents must not assume envelope fields.

## Production checks (Safari / CSRF)

Symptom **`csrf mismatch`** on `POST /api/login` means the browser sent an `embedded_csrf` cookie, but **no cookie value matched** the `csrf_token` in the JSON body (often stale iframe HTML vs cookie jar after BFCache / ITP).

Verify:

1. **`GET /embedded-login` response** includes `Cache-Control: no-store` (Auth Service sets this) and **two** `Set-Cookie` lines for `embedded_csrf` (clear then set). Do not cache this URL on CDN or nginx `proxy_cache`.
2. **HTTPS issuer** so the CSRF cookie is `SameSite=None; Secure` (required for third-party iframe POSTs).
3. **Reverse proxy** must forward all `Set-Cookie` headers to the client without merging; do not strip cookies for `/embedded-login` or `/api/*`.
4. **SDK / parent**: `@auth-service/embedded-auth` `load()` adds `_pv` and optional `return_to` (see [return_to and new-tab sign-in](#return_to-and-new-tab-sign-in)); parents that set `iframe.src` manually should mirror that behavior.

## JSON Schema (informative)

A formal JSON Schema can be published alongside this file; the Rust validator in `domain::embedded_ui_theme` and the TypeScript SDK types are the **normative** implementation.

## See also

- [ADR: optional BFF / code exchange for embedded](adr/EMBEDDED_BFF_AND_CODE_EXCHANGE.md)
