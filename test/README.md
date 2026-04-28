# Security test harness (`Makefile.test`)

Automates **SCA**, **container image CVE scan**, **SAST**, **secrets**, **RBAC / admin-escalation HTTP probe**, **DAST** (OWASP ZAP baseline), and **external header smoke** checks for `backend` + `dashboard-ui`, using Docker Compose from the repo root.

## Prerequisites

- Docker + `docker compose`
- `make`, `python3`, `curl`
- First runs pull scanner images (`trivy`, `gitleaks`, `semgrep`, `zaproxy`, `node`, `rust`).

## One-shot full run

```bash
# From repository root (requires .env for compose — see .env.example)
make -f Makefile.test security-all
```

Artifacts (JSON/HTML) go to `test/reports/` (gitignored). Краткий разбор прогона и слабых мест: [`test/REPORT.md`](REPORT.md) (в репозитории, обновляйте вручную после значимых изменений пайплайна).

Teardown:

```bash
make -f Makefile.test security-down
```

## Targets

| Target | What it does |
|--------|----------------|
| `security-up` | `Makefile.docker` **up** + **migrate** + wait for `/health` and dashboard `/api/health` |
| `security-down` | `Makefile.docker` **down** |
| `security-secrets` | Gitleaks (`test/config/gitleaks.toml`) |
| `security-sast` | Semgrep (`p/security-audit` + `p/secrets`; no `auto` — it requires metrics on); **fails on `ERROR` severity** findings |
| `security-deps` | `npm audit` (dashboard, lockfile-only) + `cargo audit` (workspace); **fails on High/Critical** (npm); Rust: **severity high/critical or CVSS ≥ 7** |
| `security-images` | Trivy on **built** compose images `backend` + `dashboard-ui`; **HIGH,CRITICAL** (resolves image ID even when containers are stopped — labels / `{project}-{service}:latest`) |
| `security-dast` | ZAP baseline vs `host.docker.internal:8080` / `:5173` and internal `container:auth-backend` (reports dir mounted at container **`/zap/wrk`**, as required by the image) |
| `security-headers` | Curl checks on dashboard + backend `/health` |
| `security-internal` | `wget` `/health` **inside** `backend` container |
| `security-all` | Ordered: secrets → sast → deps → up → internal → headers → **admin-escalation probe** → dast → images |

## URLs / DAST scope

Documented in [`test/config/targets.md`](config/targets.md). Default ZAP targets are unauthenticated: `/health`, `/.well-known/openid-configuration`, dashboard `/`.

## Baselines / allowlists

| File | Purpose |
|------|---------|
| [`test/config/.trivyignore`](config/.trivyignore) | CVE IDs to ignore after triage |
| [`test/config/gitleaks.toml`](config/gitleaks.toml) | Gitleaks allowlist / paths |
| [`test/config/.semgrepignore`](config/.semgrepignore) | Paths excluded from Semgrep |
| [`test/config/zap-baseline-rules.tsv`](config/zap-baseline-rules.tsv) | ZAP baseline rule config (non-comment rows enable `-c`) |

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `BACKEND_EXTERNAL_URL` | `http://127.0.0.1:8080` | Host-side checks / curl; `security-headers` expects **200** on `/.well-known/openid-configuration` (clear `OIDC__SERVER_METADATA_URL` or set `OIDC__METADATA_PROXY_FALLBACK=true` if upstream is down) |
| `DASHBOARD_EXTERNAL_URL` | `http://127.0.0.1:5173` | Dashboard nginx on host |
| `DOCKER_HOST_ADDR` | `host.docker.internal` | Target host from ZAP container |
| `COMPOSE_FILE` | `$ROOT/docker-compose.yml` | Alternate compose file |
| `SKIP_CARGO_AUDIT` | unset | Set to `1` to skip `cargo-audit` step |
| `SECURITY_ESCALATION_SKIP` | unset | Set to `1` to skip DB seed + admin-escalation step inside `security-all` |
| `AUTH__ADMIN_API_AUDIENCE` | (from `.env`) | Passed to the probe as `--admin-audience` (same as production dashboard tokens) |
| `ESCALATION_TENANT_ID` / `ESCALATION_REGULAR_EMAIL` / `ESCALATION_REGULAR_PASSWORD` | built-in seed defaults | Override if you do not use the bundled SQL seed |

## cargo-audit version

The Docker path installs **cargo-audit 0.22.1**. **0.21.x** fails on current `rustsec/advisory-db` when an advisory uses **CVSS 4.0** (`unsupported CVSS version: 4.0`). If you use the host `cargo audit` branch, upgrade local **cargo-audit** to **≥ 0.22.0**.

## Linux note

ZAP uses `host.docker.internal`; on Linux, scripts pass `--add-host=host.docker.internal:host-gateway` automatically. If it still fails, set `DOCKER_HOST_ADDR` to your bridge gateway IP.

## Gating policy

- **npm / Trivy**: High + Critical → fail  
- **cargo-audit**: advisory `severity` high/critical or **CVSS score ≥ 7**  
- **Semgrep**: only **`ERROR`** severity results fail (closest mapping to high-impact rules)  
- **Gitleaks**: any leak → fail  
- **ZAP**: High/Critical in JSON report → fail  

Adjust baselines above before weakening gates in shared branches.

## JWT access/refresh TTL check (Docker)

From repository root (requires `.env` for compose, same as `security-up`):

```bash
sh test/scripts/run-jwt-ttl.sh
```

This uses [`test/docker/jwt-ttl.override.yml`](docker/jwt-ttl.override.yml) (optional TTL hints), migrates, applies the security probe seed, then runs [`test/scripts/check-jwt-ttl.py`](scripts/check-jwt-ttl.py). Waits are driven by the API `expires_in` and refresh JWT `exp` (server enforces minimum access **60s** and refresh **300s** for typical login). Expect on the order of **~8–9 minutes** wall time after the stack is up: access is rejected only after JWT `exp` **plus** `jsonwebtoken` default **60s leeway**, then the refresh JWT wait (min refresh TTL 300s + same leeway).

## Parallel refresh race check (optional)

With the stack up and valid credentials, run:

`python3 test/scripts/stress-parallel-refresh.py --base-url http://127.0.0.1:8080 --tenant-id <uuid> --email <e> --password <p> --trials 100`

Expect exit code **0** after the atomic refresh fix. Use `--allow-double-200` only when investigating regressions. If logins return **429**, wait or reset Redis IP/login counters before re-running.

## Admin privilege escalation checks (in `security-all`)

[`run-security-escalation.sh`](scripts/run-security-escalation.sh) runs after header smoke: it reads a **whitelist** of keys from repo **`.env`** via [`dotenv_whitelist_export.py`](scripts/dotenv_whitelist_export.py) (not `source .env`, so values with spaces such as `VITE_APP_NAME=Auth Admin` do not break the shell). Exported keys include `AUTH__ADMIN_API_AUDIENCE`, `BACKEND_EXTERNAL_URL`, and optional `ESCALATION_*` / `SECURITY_ESCALATION_SKIP`. Then it applies [`test/sql/security_escalation_seed.sql`](sql/security_escalation_seed.sql) via the **compose** Postgres service (idempotent probe user **without** `admin` role) and runs [`check-admin-privilege-escalation.py`](scripts/check-admin-privilege-escalation.py). Set **`SECURITY_ESCALATION_SKIP=1`** to skip seed + checks (e.g. external Postgres without the bundled seed).

The Python script runs **negative** HTTP checks: log in as the probe user, use the same **admin API audience** as the dashboard (`AUTH__ADMIN_API_AUDIENCE`), then assert:

- the access JWT **does not** list `admin` in `roles`;
- **GET** `/admin/users`, `/admin/rbac`, `/admin/dashboard/stats` are **not** successful (no 2xx);
- **POST** `/auth/register` with that bearer is **not** successful;
- **GET** `/admin/session` may return 200 (it uses `require_admin_audience` only) but **`is_admin` and `is_deployment_global_admin` must be false** — use a tenant user **not** listed in `AUTH__GLOBAL_ADMIN_USER_IDS`;
- a second login with a **non–admin-audience** string must not yield a token that can **GET** `/admin/users` with 2xx.

If any check shows illegal admin claims or access to **`require_admin`** endpoints, the script exits **1**. Missing credentials or login failure exits **2**.

From repo root (stack up, Postgres user exists without `admin` role):

```bash
python3 test/scripts/check-admin-privilege-escalation.py \
  --base-url http://127.0.0.1:8080 \
  --tenant-id '<uuid>' \
  --email 'user-without-admin@example.com' \
  --password '...'
```

Or with `make` (required env vars must be set):

```bash
export ESCALATION_TENANT_ID=...
export ESCALATION_REGULAR_EMAIL=...
export ESCALATION_REGULAR_PASSWORD=...
# optional: ESCALATION_ADMIN_AUDIENCE ESCALATION_WRONG_AUDIENCE BACKEND_EXTERNAL_URL
# optional positive smoke: ESCALATION_ADMIN_EMAIL ESCALATION_ADMIN_PASSWORD
make -f Makefile.test security-admin-escalation
```

Playwright [`dashboard-ui/tests/e2e/login-dashboard.spec.ts`](../dashboard-ui/tests/e2e/login-dashboard.spec.ts) only asserts UI routing (dashboard vs access denied); it does not replace the script above for API-level guarantees.
