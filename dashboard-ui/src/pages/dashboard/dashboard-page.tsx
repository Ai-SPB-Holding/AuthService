import { useCallback, useMemo } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { useAuthStore } from "@/features/auth/auth-store";
import { dashboardStatsKey } from "@/features/dashboard/use-dashboard-stats";
import { useDashboardStats } from "@/features/dashboard/use-dashboard-stats";
import { rbacQueryKey } from "@/features/rbac/use-rbac-query";
import { useSSE } from "@/hooks/use-sse";
import { getErrorMessage } from "@/shared/api/api-error";
import { StatsCards } from "@/widgets/stats-cards/stats-cards";
import { Card } from "@/shared/ui/card";
import { Button } from "@/shared/ui/button";
import { EmptyState, InlineError } from "@/shared/ui/status-blocks";

function formatCount(n: number) {
  return n.toLocaleString();
}

export function DashboardPage() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError, error, refetch, isFetching } = useDashboardStats();
  const isDeploymentGlobalAdmin = useAuthStore((s) => s.isDeploymentGlobalAdmin);

  const onSse = useCallback(
    (ev: MessageEvent<string>) => {
      if (String(ev.data ?? "").length > 0) {
        void queryClient.invalidateQueries({ queryKey: ["users"] });
        void queryClient.invalidateQueries({ queryKey: dashboardStatsKey });
        void queryClient.invalidateQueries({ queryKey: rbacQueryKey });
      }
    },
    [queryClient],
  );

  useSSE(onSse);

  const stats = useMemo(() => {
    if (!data) {
      return [
        { label: "Users", value: "—" },
        { label: "OAuth clients", value: "—" },
        { label: "Roles", value: "—" },
        { label: "Active users (24h)", value: "—" },
        { label: "Logins / hour", value: "—" },
        { label: "Auth errors / hour", value: "—" },
      ];
    }
    return [
      { label: "Users", value: formatCount(data.user_count) },
      { label: "OAuth clients", value: formatCount(data.oauth_clients_count) },
      { label: "Roles", value: formatCount(data.roles_count) },
      { label: "Active users (24h)", value: formatCount(data.active_users_24h) },
      { label: "Logins / hour", value: formatCount(data.logins_last_hour) },
      { label: "Auth errors / hour", value: formatCount(data.auth_failures_last_hour) },
    ];
  }, [data]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-slate-500 dark:text-slate-400">
          {isDeploymentGlobalAdmin
            ? "Aggregated across all tenants (your user is in AUTH__GLOBAL_ADMIN_USER_IDS or AUTH__AUTH_SERVICE_DEPLOYMENT_ADMINS on the API). Logins and auth failures are from password flow."
            : "Metrics for the tenant in your access token only. Logins and auth failures are from password flow."}
        </p>
        {isFetching && !isLoading && <span className="text-xs text-slate-500">Updating…</span>}
      </div>

      {isError && (
        <InlineError title="Could not load dashboard" message={getErrorMessage(error)}>
          <Button className="mt-3" type="button" variant="outline" onClick={() => void refetch()}>
            Retry
          </Button>
        </InlineError>
      )}

      {isLoading && !isError && (
        <p className="text-sm text-slate-500" role="status">
          Loading stats…
        </p>
      )}

      {!isError && <StatsCards stats={stats} />}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <h3 className="mb-4 text-sm font-semibold">Login activity</h3>
          <EmptyState
            title="No time-series yet"
            description="Per-minute charts can be added when the API exposes historical series."
          />
        </Card>
        <Card>
          <h3 className="mb-4 text-sm font-semibold">Error rate</h3>
          <EmptyState
            title="No time-series yet"
            description="The summary cards show failed password logins in the last hour."
          />
        </Card>
      </div>
    </div>
  );
}
