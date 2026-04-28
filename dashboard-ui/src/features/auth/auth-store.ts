import { create } from "zustand";
import axios from "axios";

import {
  loginRequestRaw,
  logoutRequest,
  refreshRequest,
  type LoginPayload,
} from "@/services/auth/auth-api";
import { parseAccessTokenPayload } from "@/shared/lib/jwt";
import {
  clearAuthSession,
  readAudienceFromStorage,
  readRefreshTokenFromStorage,
  writeAuthSession,
} from "@/shared/lib/auth-storage";
import { parseApiError } from "@/shared/api/api-error";
import { endpoints } from "@/shared/api/endpoints";
import { env } from "@/shared/config/env";
import type { AuthTokens } from "@/shared/types/auth";
import { isAuthTokens, isLoginMfaRequired, isLoginTotpEnrollmentRequired } from "@/shared/types/auth";
import type { AdminSessionInfo } from "@/shared/types/settings";

let bootstrapPromise: Promise<void> | null = null;

export type DashboardAccess = "admin" | "client_settings" | null;

export type LoginFlowResult =
  | { status: "success" }
  | { status: "totp_enrollment"; enrollmentToken: string; audience: string }
  | { status: "mfa"; stepUpToken: string; audience: string };

type AuthStore = {
  accessToken: string | null;
  refreshToken: string | null;
  /** Last successful login audience (required for refresh). */
  audience: string | null;
  roles: string[];
  isAuthenticated: boolean;
  isLoading: boolean;
  isBootstrapping: boolean;
  /** Loaded after `/admin/session` when a Bearer token exists. */
  sessionLoaded: boolean;
  /** Who may use the dashboard: full admin, or only Settings (OAuth client delegate). */
  accessLevel: DashboardAccess;
  /** Set when `sub` is in deployment admin allowlist — lists/metrics span all tenants. */
  isDeploymentGlobalAdmin: boolean;
  login: (payload: LoginPayload) => Promise<LoginFlowResult>;
  /** After TOTP enrollment verification (enrollment bearer returns tokens in `/2fa/verify`). */
  finishLoginWithTokens: (tokens: AuthTokens, audience: string) => Promise<void>;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
  bootstrap: () => Promise<void>;
  loadAdminSession: () => Promise<void>;
  setRoles: (roles: string[]) => void;
};

const DEFAULT_AUDIENCE = env.defaultAudience;

function rolesFromAccessToken(accessToken: string): string[] {
  const payload = parseAccessTokenPayload(accessToken);
  return payload?.roles ?? [];
}

function resolveAudience(get: () => AuthStore): string {
  const a = get().audience ?? readAudienceFromStorage() ?? DEFAULT_AUDIENCE;
  return a;
}

async function fetchAdminSessionRequest(accessToken: string): Promise<AdminSessionInfo> {
  const res = await axios.get<AdminSessionInfo>(`${env.apiBaseUrl}${endpoints.admin.session}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    timeout: 15_000,
    validateStatus: () => true,
  });
  if (res.status !== 200 || !res.data) {
    throw new Error("admin session unavailable");
  }
  return res.data;
}

export const useAuthStore = create<AuthStore>((set, get) => ({
  accessToken: null,
  refreshToken: null,
  audience: null,
  roles: [],
  isAuthenticated: false,
  isLoading: false,
  isBootstrapping: true,
  sessionLoaded: false,
  accessLevel: null,
  isDeploymentGlobalAdmin: false,

  loadAdminSession: async () => {
    const token = get().accessToken;
    if (!token) {
      set({ sessionLoaded: true, accessLevel: null, isDeploymentGlobalAdmin: false });
      return;
    }
    try {
      const data = await fetchAdminSessionRequest(token);
      const global = Boolean(data.is_deployment_global_admin);
      if (data.is_admin) {
        set({ accessLevel: "admin", sessionLoaded: true, isDeploymentGlobalAdmin: global });
      } else if (data.is_client_settings_member) {
        set({ accessLevel: "client_settings", sessionLoaded: true, isDeploymentGlobalAdmin: global });
      } else {
        set({ accessLevel: null, sessionLoaded: true, isDeploymentGlobalAdmin: false });
      }
    } catch {
      set({ accessLevel: null, sessionLoaded: true, isDeploymentGlobalAdmin: false });
    }
  },

  finishLoginWithTokens: async (tokens, audience) => {
    const refreshToken = tokens.refresh_token ?? null;
    set({
      accessToken: tokens.access_token,
      refreshToken,
      audience,
      roles: rolesFromAccessToken(tokens.access_token),
      isAuthenticated: true,
      sessionLoaded: false,
    });
    if (refreshToken) {
      writeAuthSession(refreshToken, audience);
    }
    await get().loadAdminSession();
  },

  login: async (payload) => {
    set({ isLoading: true });
    try {
      const raw = await loginRequestRaw({
        ...payload,
        set_idp_session: env.setIdpSessionOnLogin ? true : undefined,
      });
      if (isLoginTotpEnrollmentRequired(raw)) {
        return {
          status: "totp_enrollment",
          enrollmentToken: raw.enrollment_token,
          audience: payload.audience,
        };
      }
      if (isLoginMfaRequired(raw)) {
        return {
          status: "mfa",
          stepUpToken: raw.step_up_token,
          audience: payload.audience,
        };
      }
      if (!isAuthTokens(raw)) {
        throw new Error("Unexpected login response");
      }
      const tokens = raw;
      await get().finishLoginWithTokens(tokens, payload.audience);
      return { status: "success" };
    } catch (e) {
      const err = parseApiError(e);
      set({
        isAuthenticated: false,
        accessToken: null,
        refreshToken: null,
        roles: [],
        sessionLoaded: true,
        accessLevel: null,
        isDeploymentGlobalAdmin: false,
      });
      clearAuthSession();
      throw err;
    } finally {
      set({ isLoading: false });
    }
  },

  refresh: async () => {
    const rt = get().refreshToken ?? readRefreshTokenFromStorage();
    const audience = resolveAudience(get);
    if (!rt) {
      throw new Error("No refresh token");
    }
    const tokens = await refreshRequest(rt, audience);
    const newRefresh = tokens.refresh_token ?? rt;
    set({
      accessToken: tokens.access_token,
      refreshToken: newRefresh,
      audience,
      roles: rolesFromAccessToken(tokens.access_token),
      isAuthenticated: true,
      sessionLoaded: false,
    });
    writeAuthSession(newRefresh, audience);
    await get().loadAdminSession();
  },

  logout: async () => {
    const rt = get().refreshToken ?? readRefreshTokenFromStorage();
    if (rt) {
      try {
        await logoutRequest(rt);
      } catch {
        // Best effort
      }
    }

    clearAuthSession();
    set({
      accessToken: null,
      refreshToken: null,
      audience: null,
      roles: [],
      isAuthenticated: false,
      sessionLoaded: true,
      accessLevel: null,
      isDeploymentGlobalAdmin: false,
    });
  },

  bootstrap: async () => {
    if (bootstrapPromise) {
      return bootstrapPromise;
    }
    bootstrapPromise = (async () => {
      set({ isBootstrapping: true });
      const storedRt = readRefreshTokenFromStorage();
      const storedAudience = readAudienceFromStorage() ?? DEFAULT_AUDIENCE;

      if (storedRt) {
        set({ refreshToken: storedRt, audience: storedAudience });
        try {
          await get().refresh();
        } catch {
          await get().logout();
        }
      } else {
        set({ isAuthenticated: false, accessToken: null, roles: [], sessionLoaded: true, accessLevel: null, isDeploymentGlobalAdmin: false });
      }
      set({ isBootstrapping: false });
    })().finally(() => {
      bootstrapPromise = null;
    });
    return bootstrapPromise;
  },

  setRoles: (roles) => set({ roles }),
}));
