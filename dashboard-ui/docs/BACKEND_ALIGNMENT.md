# Frontend / backend contract alignment

This document tracks what the dashboard UI expects versus what the Rust service currently exposes, so both can evolve together.

## Auth (implemented on both sides)

| Endpoint | Method | Body | Notes |
|----------|--------|------|------|
| `/auth/login` | POST | `tenant_id`, `email`, `password`, `audience` | Returns `TokenPair` with `access_token`, `refresh_token` |
| `/auth/refresh` | POST | `refresh_token`, optional `audience` (ignored) | New pair; `aud` is taken from the refresh token JWT. UI may keep sending `audience` for compatibility. |
| `/auth/logout` | POST | `refresh_token` | Best-effort revoke |

Access token JWT includes `roles`, `permissions`, `tenant_id` (see `AccessClaims` in backend). The UI decodes the access token payload to populate `roles` in the client store (not signature-verified on the client).

## Errors (target shape)

**Current:** `{ "error": "<string>" }` with appropriate HTTP status.

**Target for richer UI:**

```json
{
  "error": "human readable message",
  "code": "VALIDATION_ERROR",
  "details": { "field": "email" },
  "request_id": "uuid"
}
```

The UI maps any response to `AppApiError` with `httpStatus`, `message`, optional `code` / `requestId`, and `raw` for logs.

## Admin resource list (gap)

The dashboard needs **collection** endpoints with consistent query parameters, for example:

`GET /admin/users?page=1&limit=50&q=…&sort=email&order=asc`

Response:

```json
{
  "data": [ { "id": "…", "tenant_id": "…", "email": "…", "is_active": true, … } ],
  "meta": { "page": 1, "limit": 50, "total": 123 }
}
```

Same pattern for `clients`, `roles`, `permissions` as needed.

**Current:** only `POST` + `GET/PUT/DELETE /:id` per resource; no list. `GET /:id` returns existence-style payloads in some handlers — the UI needs full entities for edit forms.

## Create user (gap)

**Current backend** `CreateUserRequest`: `tenant_id`, `email`, `password_hash`.

**Dashboard** sends `password` (plain) and expects the API to hash server-side (recommended), e.g. extend the handler to accept `password` and hash with the same module as login, or add a dedicated internal endpoint.

Until then, “Create user” in the UI may return `400` — treat as a known integration gap.

## RBAC (future)

- Endpoints to assign roles/permissions to users (e.g. `POST /admin/users/:id/roles`).
- Route guards in the UI already support `roles?: string[]` on `ProtectedRoute` once the JWT (or `/me`) exposes roles beyond a single `user` role.

## CORS

If the dashboard is served from a different origin than the API, the API must allow that origin. The UI uses `withCredentials: true` for cookies if you later move tokens to `HttpOnly` cookies.

## OIDC

The dashboard uses `/auth/*` for the session. The partial OIDC routes in the backend are not used by this SPA. Standard OIDC client libraries would require a more complete `authorize` redirect + `token` form post contract.

## OpenAPI

Providing an OpenAPI 3.1 (or JSON Schema) spec as the source of truth would allow generated types for the UI and fewer contract drift issues.
