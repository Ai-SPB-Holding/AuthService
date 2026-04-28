# ADR: Optional BFF and authorization-code exchange for embedded login

## Status

Proposed (not implemented in this repository revision).

## Context

The hosted `/embedded-login` flow currently returns **access** and **refresh** tokens to the **parent** window via `postMessage`. Any host-page JavaScript can read these tokens, so XSS on the **parent** origin is equivalent to token theft.

## Decision (future)

For integrations that need stronger browser-side protection:

1. **Option A — BFF (backend for frontend)**  
   - Parent never holds long-lived `refresh_token` in JS.  
   - Parent sends the refresh token only to a same-origin BFF.  
   - BFF stores refresh in **httpOnly, Secure, SameSite** cookies and exchanges for access on behalf of the SPA.

2. **Option B — One-time code instead of raw tokens in `postMessage`**  
   - Iframe finishes login server-side, mints a **one-time, short-TTL** `code` bound to `client_id` + `redirect_uri` + PKCE.  
   - Iframe posts `{ type: "AUTH_CODE", code }` (or v2 envelope).  
   - Parent (or BFF) exchanges `code` at `POST /token` with `code_verifier` (PKCE).  
   - Aligns with standard OAuth2 security model; larger backend change.

## Consequences

- **Pros:** Reduces window of token exposure; enables stricter threat model for regulated industries.  
- **Cons:** More moving parts; BFF is mandatory for full benefit of Option A; Option B requires new tables and hardening of code TTL + replay resistance.

## Links

- [Embedded iframe protocol](../EMBEDDED_IFRAME_PROTOCOL.md)
