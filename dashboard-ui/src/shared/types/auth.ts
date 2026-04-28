/** Decoded access token (same shape as backend `AccessClaims`). */
export type AccessTokenPayload = {
  sub: string;
  exp?: number;
  iss?: string;
  aud?: string;
  roles: string[];
  permissions?: string[];
  tenant_id?: string;
};

export type JwtClaims = AccessTokenPayload;

export type AuthTokens = {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
};

/** Response to `POST /auth/login` when admin must finish TOTP under global 2FA policy. */
export type LoginTotpEnrollmentRequired = {
  totp_enrollment_required: true;
  enrollment_token: string;
  token_type: string;
  expires_in: number;
};

export function isAuthTokens(x: unknown): x is AuthTokens {
  if (x === null || typeof x !== "object") {
    return false;
  }
  const o = x as Record<string, unknown>;
  return typeof o.access_token === "string" && typeof o.token_type === "string" && typeof o.expires_in === "number";
}

export function isLoginTotpEnrollmentRequired(x: unknown): x is LoginTotpEnrollmentRequired {
  if (x === null || typeof x !== "object") {
    return false;
  }
  const o = x as Record<string, unknown>;
  return (
    o.totp_enrollment_required === true &&
    typeof o.enrollment_token === "string" &&
    typeof o.expires_in === "number"
  );
}

/** Response when user TOTP is already enabled — second step: POST /auth/login/mfa. */
export type LoginMfaRequired = {
  mfa_required: true;
  step_up_token: string;
  token_type: string;
  expires_in: number;
};

export function isLoginMfaRequired(x: unknown): x is LoginMfaRequired {
  if (x === null || typeof x !== "object") {
    return false;
  }
  const o = x as Record<string, unknown>;
  return o.mfa_required === true && typeof o.step_up_token === "string" && typeof o.expires_in === "number";
}
