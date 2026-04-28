export const endpoints = {
  auth: {
    login: "/auth/login",
    loginMfa: "/auth/login/mfa",
    refresh: "/auth/refresh",
    logout: "/auth/logout",
  },
  twoFactor: {
    setup: "/2fa/setup",
    verify: "/2fa/verify",
  },
  /** Backend admin routes (Bearer + `admin` role). */
  admin: {
    dashboard: {
      stats: "/admin/dashboard/stats",
    },
    rbac: "/admin/rbac",
    tenantIds: {
      generate: "/admin/tenant-ids/generate",
    },
    users: {
      list: "/admin/users",
      create: "/admin/users",
      detail: (id: string) => `/admin/users/${id}`,
      patch: (id: string) => `/admin/users/${id}`,
      update: (id: string) => `/admin/users/${id}`,
      remove: (id: string) => `/admin/users/${id}`,
      sendVerificationEmail: (id: string) => `/admin/users/${id}/send-verification-email`,
      verifyEmail: (id: string) => `/admin/users/${id}/verify-email`,
      resetEmailVerification: (id: string) => `/admin/users/${id}/reset-email-verification`,
    },
    clients: {
      list: "/admin/clients",
      create: "/admin/clients",
      detail: (id: string) => `/admin/clients/${id}`,
      generateId: "/admin/clients/generate-id",
      /** Per-client TOTP (admin operations on a user). */
      userClient2fa: (clientRowId: string, userId: string) => `/admin/clients/${clientRowId}/users/${userId}/2fa`,
    },
    auditLogs: "/admin/audit-logs",
    session: "/admin/session",
    settings: "/admin/settings",
    sessions: {
      list: "/admin/sessions",
      revoke: (id: string) => `/admin/sessions/${id}/revoke`,
    },
  },
};
