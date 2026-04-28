import { lazy } from "react";

export const LoginPage = lazy(() => import("@/pages/login/login-page").then((m) => ({ default: m.LoginPage })));
export const AccessDeniedPage = lazy(() =>
  import("@/pages/access-denied/access-denied-page").then((m) => ({ default: m.AccessDeniedPage })),
);
export const DashboardPage = lazy(() => import("@/pages/dashboard/dashboard-page").then((m) => ({ default: m.DashboardPage })));
export const UsersPage = lazy(() => import("@/pages/users/users-page").then((m) => ({ default: m.UsersPage })));
export const ClientsPage = lazy(() => import("@/pages/clients/clients-page").then((m) => ({ default: m.ClientsPage })));
export const RolesPage = lazy(() => import("@/pages/roles/roles-page").then((m) => ({ default: m.RolesPage })));
export const SessionsPage = lazy(() => import("@/pages/sessions/sessions-page").then((m) => ({ default: m.SessionsPage })));
export const AuditPage = lazy(() => import("@/pages/audit/audit-page").then((m) => ({ default: m.AuditPage })));
export const SettingsPage = lazy(() => import("@/pages/settings/settings-page").then((m) => ({ default: m.SettingsPage })));
