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
| `AUTH_SUCCESS`  | iframe → parent  | `access_token`, `refresh_token`; optional `expires_in` if API returns it. Envelope + token fields. |
| `AUTH_ERROR`    | iframe → parent  | `error` (machine code), `message` (human-readable). Envelope + error fields. |

## Handshake (recommended, v2)

1. Iframe dispatches `EMBED_READY` with a fresh `nonce_iframe` (also in the envelope as `nonce`).
2. Parent sends `INIT` with a new `nonce` and, if desired, `parent_origin: window.location.origin`.
3. Iframe responds with `INIT_ACK` with `allowed: true` if `event.origin` is in the allowlist, else `allowed: false`.

The iframe will still complete login; `INIT` is for SDK alignment and gating of optional behavior.

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

- Success: `{ "type": "AUTH_SUCCESS", "access_token": "...", "refresh_token": "..." }`
- Error: `{ "type": "AUTH_ERROR", "error": "CODE", "message": "..." }`

No `v` / `ts` / `nonce` / `source` fields. Parents must not assume envelope fields.

## JSON Schema (informative)

A formal JSON Schema can be published alongside this file; the Rust validator in `domain::embedded_ui_theme` and the TypeScript SDK types are the **normative** implementation.

## See also

- [ADR: optional BFF / code exchange for embedded](adr/EMBEDDED_BFF_AND_CODE_EXCHANGE.md)
