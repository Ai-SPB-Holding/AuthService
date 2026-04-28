import { useNavigate } from "react-router-dom";

import { useAuth } from "@/features/auth/use-auth";
import { Button } from "@/shared/ui/button";
import { Card } from "@/shared/ui/card";

export function AccessDeniedPage() {
  const { logout } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 p-4 dark:bg-slate-950">
      <Card className="max-w-md space-y-4 p-6">
        <h1 className="text-lg font-semibold">Access denied</h1>
        <p className="text-sm text-slate-600 dark:text-slate-300">
          The admin dashboard is only available to users with the <strong>admin</strong> role. Ask an administrator to grant you access, or use a
          different account.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            onClick={() => {
              void logout();
              navigate("/login", { replace: true });
            }}
          >
            Sign out
          </Button>
          <Button variant="ghost" onClick={() => navigate("/login", { replace: true })}>
            Back to sign in
          </Button>
        </div>
      </Card>
    </div>
  );
}
