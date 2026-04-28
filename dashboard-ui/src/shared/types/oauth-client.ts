/** Row from `GET /admin/clients` / `GET /admin/clients/:id`. */
export type OAuthClientRow = {
  id: string;
  /** Organization this OAuth client belongs to; use when filtering for a specific user. */
  tenant_id: string;
  client_id: string;
  client_type?: "public" | "confidential";
  client_secret_masked: string;
  redirect_uri: string;
  /** JSON array of allowed redirect URIs from the API. */
  allowed_redirect_uris: unknown;
  scopes: string;
  allow_user_registration?: boolean;
  /** Per-OAuth-client TOTP policy: `off` | `optional` | `required`. */
  mfa_policy?: "off" | "optional" | "required" | string;
  /** User may enroll Google Authenticator for this client (when policy allows). */
  allow_client_totp_enrollment?: boolean;
  /** When true, `GET /embedded-login?client_id=...` is allowed for this client. */
  embedded_login_enabled?: boolean;
  /** JWT `aud` override for embedded login; default is public `client_id`. */
  embedded_token_audience?: string | null;
  /** Allowed parent page origins for iframe CSP and postMessage. */
  embedded_parent_origins?: unknown;
  /** v2 `postMessage` protocol (envelope, INIT, THEME). */
  embedded_protocol_v2?: boolean;
  /** Whitelisted design tokens; validated on save. */
  embedded_ui_theme?: unknown;
  user_schema?: unknown;
  created_at: string;
  /** After migration 0013 — RFC 6749 token endpoint client auth method. */
  token_endpoint_auth_method?: string;
  grant_types?: string[];
  response_types?: string[];
  require_pkce?: boolean;
  embedded_flow_mode?: "code_exchange" | "bff_cookie" | "legacy_postmessage" | string;
  use_v2_endpoints_only?: boolean;
};
