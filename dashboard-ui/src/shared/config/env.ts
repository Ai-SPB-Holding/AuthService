const dev = import.meta.env.DEV;

/**
 * Local-only demo prefill; never enable in production builds.
 */
function loginDevDefaults() {
  const aud = (import.meta.env.VITE_DEV_AUDIENCE as string) ?? import.meta.env.VITE_DEFAULT_AUDIENCE ?? "auth-service";
  if (!dev) {
    return { tenant: "", email: "", password: "", audience: aud };
  }
  return {
    tenant: import.meta.env.VITE_DEV_TENANT_ID ?? "",
    email: import.meta.env.VITE_DEV_EMAIL ?? "",
    password: import.meta.env.VITE_DEV_PASSWORD ?? "",
    audience: aud,
  };
}

export const env = {
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080",
  appName: import.meta.env.VITE_APP_NAME ?? "Auth Admin",
  sseUrl: import.meta.env.VITE_SSE_URL ?? "http://localhost:8080/events",
  /** Default admin API audience (must match `AUTH__ADMIN_API_AUDIENCE` on the server). */
  defaultAudience: import.meta.env.VITE_DEFAULT_AUDIENCE ?? "auth-service",
  /** Shown on login to reduce confusion between environments (e.g. dev, staging, prod). */
  envName: (import.meta.env.VITE_ENV_NAME as string) ?? (dev ? "development" : "production"),
  /** If true, login requests `set_idp_session` for OIDC browser authorize flow. */
  setIdpSessionOnLogin: import.meta.env.VITE_SET_IDP_SESSION === "true",
  loginDevDefaults,
};
