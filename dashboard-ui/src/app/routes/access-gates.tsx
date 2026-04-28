import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";

import { useAuthStore } from "@/features/auth/auth-store";

/** Full admin UI (Dashboard, Users, …). Client delegates are redirected to Settings. */
export function RequireFullAdmin({ children }: { children: ReactNode }) {
  const sessionLoaded = useAuthStore((s) => s.sessionLoaded);
  const accessLevel = useAuthStore((s) => s.accessLevel);
  if (!sessionLoaded) {
    return (
      <p className="text-sm text-slate-500" role="status">
        Checking permissions…
      </p>
    );
  }
  if (accessLevel === "admin") {
    return <>{children}</>;
  }
  if (accessLevel === "client_settings") {
    return <Navigate to="/settings" replace />;
  }
  return <Navigate to="/access-denied" replace />;
}

/** Settings tab: admins and OAuth client delegates with a `client_user_membership` row. */
export function RequireSettingsAccess({ children }: { children: ReactNode }) {
  const sessionLoaded = useAuthStore((s) => s.sessionLoaded);
  const accessLevel = useAuthStore((s) => s.accessLevel);
  if (!sessionLoaded) {
    return (
      <p className="text-sm text-slate-500" role="status">
        Checking permissions…
      </p>
    );
  }
  if (accessLevel === "admin" || accessLevel === "client_settings") {
    return <>{children}</>;
  }
  return <Navigate to="/access-denied" replace />;
}
