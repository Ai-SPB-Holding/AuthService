import { Navigate, Outlet } from "react-router-dom";

import { useAuth } from "@/features/auth/use-auth";
import { useAuthStore } from "@/features/auth/auth-store";

export function ProtectedRoute() {
  const { isAuthenticated, isBootstrapping } = useAuth();
  const sessionLoaded = useAuthStore((s) => s.sessionLoaded);
  const accessLevel = useAuthStore((s) => s.accessLevel);

  if (isBootstrapping || (isAuthenticated && !sessionLoaded)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100 dark:bg-slate-950">
        <p className="text-sm text-slate-600 dark:text-slate-300" role="status">
          Loading session…
        </p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (accessLevel === null) {
    return <Navigate to="/access-denied" replace />;
  }

  return <Outlet />;
}
