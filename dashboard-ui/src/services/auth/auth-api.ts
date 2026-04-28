import { authHttp } from "@/shared/api/auth-http";
import { endpoints } from "@/shared/api/endpoints";
import { env } from "@/shared/config/env";
import type { AuthTokens } from "@/shared/types/auth";
import axios from "axios";

export type LoginPayload = {
  tenant_id: string;
  email: string;
  password: string;
  audience: string;
  /** When true, server may set `idp_session` for `GET /authorize` (requires `AUTH__COOKIE_SECRET` + Same-Site). */
  set_idp_session?: boolean;
};

/** Raw JSON from `POST /auth/login` (tokens, MFA, or forced TOTP enrollment). */
export async function loginRequestRaw(
  payload: LoginPayload,
): Promise<unknown> {
  const { data } = await authHttp.post<unknown>(endpoints.auth.login, payload);
  return data;
}

/** Second step after `mfa_required` (user TOTP already enrolled). */
export async function loginMfaRequest(
  stepUpToken: string,
  totp: string,
) {
  const { data } = await authHttp.post<AuthTokens>(endpoints.auth.loginMfa, {
    step_up_token: stepUpToken,
    totp,
  });
  return data;
}

export type TotpSetupResponse = { otpauth_url: string; secret_base32: string };

/** `POST /2fa/setup` with a `totp-enroll` or access JWT. */
export async function totpSetupRequest(
  enrollmentOrAccessToken: string,
): Promise<TotpSetupResponse> {
  const { data } = await axios.post<TotpSetupResponse>(
    `${env.apiBaseUrl}${endpoints.twoFactor.setup}`,
    {},
    {
      headers: { Authorization: `Bearer ${enrollmentOrAccessToken}` },
      timeout: 15_000,
    },
  );
  return data;
}

export type TotpVerifyEnrollmentResponse = AuthTokens & {
  ok: boolean;
  totp_enabled: boolean;
};

/** `POST /2fa/verify` — with enrollment token, response includes `access_token` + `refresh_token`. */
export async function totpVerifyRequest(
  enrollmentOrAccessToken: string,
  code: string,
): Promise<TotpVerifyEnrollmentResponse> {
  const { data } = await axios.post<TotpVerifyEnrollmentResponse>(
    `${env.apiBaseUrl}${endpoints.twoFactor.verify}`,
    { code },
    {
      headers: { Authorization: `Bearer ${enrollmentOrAccessToken}` },
      timeout: 15_000,
    },
  );
  return data;
}

export async function refreshRequest(refreshToken: string, audience: string) {
  const { data } = await authHttp.post<AuthTokens>(endpoints.auth.refresh, {
    refresh_token: refreshToken,
    audience,
  });
  return data;
}

export async function logoutRequest(refreshToken: string) {
  await authHttp.post(endpoints.auth.logout, { refresh_token: refreshToken });
}
