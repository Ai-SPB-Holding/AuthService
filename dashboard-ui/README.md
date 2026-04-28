# Auth Service — Admin Dashboard (`dashboard-ui`)

SPA for operating the Auth Service: login, user management (where APIs exist), and placeholder sections for clients, roles, sessions, and audit.

## Stack

- React 19, TypeScript, Vite 8
- React Router 7, TanStack Query, Zustand
- Tailwind CSS 4, react-hook-form + Zod
- Axios with normalized errors (`AppApiError`) and a separate `authHttp` client (no interceptors) to avoid import cycles

## Run

```bash
npm install
cp .env.example .env   # optional
npm run dev
```

Build: `npm run build` · Lint: `npm run lint` · Unit tests: `npm run test` · E2E: `npm run test:e2e`

## Environment

| Variable | Description |
|----------|-------------|
| `VITE_API_BASE_URL` | Backend origin (default `http://localhost:8080`) |
| `VITE_SSE_URL` | Server-Sent Events URL for live refresh hints |
| `VITE_APP_NAME` | Shown in UI copy |
| `VITE_DEV_*` | Optional local-only login form prefill (see `.env.example`); never set in production bundles |

## Architecture

- **`src/app/`** — router, providers, bootstrap
- **`src/pages/`** — route screens (lazy-loaded)
- **`src/features/`** — domain logic (auth store, users queries)
- **`src/shared/api/`** — `apiClient`, `authHttp`, `api-error` normalization, `endpoints`
- **`src/services/auth/`** — login / refresh / logout requests (refresh token + audience stored in `sessionStorage`)

Session: after login, **access token** is kept in memory; **refresh token** and **audience** are stored in `sessionStorage` so the tab can restore a session via `POST /auth/refresh`.

## Admin access

All `/admin/*` API routes require `Authorization: Bearer <access_token>` where the token includes the **`admin`** role. Roles come from the database (`user_roles` / `roles`); see repository `Makefile.users` (`user-promote-admin`).

Non-admin users who sign in are redirected to `/access-denied`. The dashboard loads live metrics from `GET /admin/dashboard/stats` (tenant-scoped).

## Backend contracts

See [docs/BACKEND_ALIGNMENT.md](docs/BACKEND_ALIGNMENT.md) for proposed list/pagination, error shape, user create (`password` vs `password_hash`), and RBAC endpoints.
