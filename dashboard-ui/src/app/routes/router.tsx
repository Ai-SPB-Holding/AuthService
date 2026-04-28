import { Suspense, type ReactNode } from "react";
import { createBrowserRouter } from "react-router-dom";

import { RequireFullAdmin, RequireSettingsAccess } from "@/app/routes/access-gates";
import { ProtectedRoute } from "@/app/routes/protected-route";
import {
  AccessDeniedPage,
  AuditPage,
  ClientsPage,
  DashboardPage,
  LoginPage,
  RolesPage,
  SessionsPage,
  SettingsPage,
  UsersPage,
} from "@/app/routes/lazy-screens";
import { PageFallback } from "@/app/routes/page-fallback";
import { AppShell } from "@/widgets/layout/app-shell";

function withSuspense(el: ReactNode) {
  return <Suspense fallback={<PageFallback />}>{el}</Suspense>;
}

export const router = createBrowserRouter([
  {
    path: "/login",
    element: withSuspense(<LoginPage />),
  },
  {
    path: "/access-denied",
    element: <ProtectedRoute />,
    children: [{ index: true, element: withSuspense(<AccessDeniedPage />) }],
  },
  {
    element: <ProtectedRoute />,
    children: [
      {
        path: "/",
        element: <AppShell />,
        children: [
          { index: true, element: withSuspense(<RequireFullAdmin><DashboardPage /></RequireFullAdmin>) },
          { path: "users", element: withSuspense(<RequireFullAdmin><UsersPage /></RequireFullAdmin>) },
          { path: "clients", element: withSuspense(<RequireFullAdmin><ClientsPage /></RequireFullAdmin>) },
          { path: "roles", element: withSuspense(<RequireFullAdmin><RolesPage /></RequireFullAdmin>) },
          { path: "sessions", element: withSuspense(<RequireFullAdmin><SessionsPage /></RequireFullAdmin>) },
          { path: "audit", element: withSuspense(<RequireFullAdmin><AuditPage /></RequireFullAdmin>) },
          { path: "settings", element: withSuspense(<RequireSettingsAccess><SettingsPage /></RequireSettingsAccess>) },
        ],
      },
    ],
  },
]);
