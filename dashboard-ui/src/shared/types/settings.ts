export type ServiceSettings = {
  require_login_2fa: boolean;
  client_mfa_enforce: boolean;
  /** `SERVER__ISSUER` — public issuer / API URL. */
  api_domain: string;
  jwt_private_key_pem_set: boolean;
  jwt_public_key_pem_set: boolean;
  cookie_secret_set: boolean;
  totp_encryption_key_b64_set: boolean;
  env_file_path: string;
  restart_required_note?: string | null;
  /** `AUTH__ACCESS_TTL_SECONDS` — default when per-client access TTL is unset. */
  default_access_ttl_seconds: number;
  /** `AUTH__REFRESH_TTL_SECONDS` — default when per-client refresh TTL is unset. */
  default_refresh_ttl_seconds: number;
  /** `AUTH__MAX_CLIENT_ACCESS_TTL_SECONDS` */
  max_client_access_ttl_seconds: number;
  /** `AUTH__MAX_CLIENT_REFRESH_TTL_SECONDS` */
  max_client_refresh_ttl_seconds: number;
};

export type AdminSessionInfo = {
  is_admin: boolean;
  is_client_settings_member: boolean;
  /** Listed in `AUTH__GLOBAL_ADMIN_USER_IDS` or `AUTH__AUTH_SERVICE_DEPLOYMENT_ADMINS` on the API. */
  is_deployment_global_admin: boolean;
};

export type SettingsUpdatePayload = {
  require_login_2fa?: boolean;
  client_mfa_enforce?: boolean;
  api_domain?: string;
  private_key_pem?: string;
  public_key_pem?: string;
  cookie_secret?: string;
  totp_encryption_key_b64?: string;
  totp_code?: string;
};

export type SettingsUpdateResult = {
  settings: ServiceSettings;
  restart_required: boolean;
};
