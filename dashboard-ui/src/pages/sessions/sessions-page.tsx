import { getErrorMessage } from "@/shared/api/api-error";
import { useRevokeSessionMutation, useSessionsQuery } from "@/features/sessions/use-sessions-query";
import type { SessionRow } from "@/features/sessions/sessions-api";
import { Button } from "@/shared/ui/button";
import { DataTable } from "@/shared/ui/table";
import { EmptyState, InlineError, ListSkeleton } from "@/shared/ui/status-blocks";

function formatWhen(iso: string) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function SessionsPage() {
  const { data, isLoading, error, isError, refetch, isFetching } = useSessionsQuery();
  const revokeM = useRevokeSessionMutation();

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Refresh-token sessions from PostgreSQL. Revoking sets <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">revoked</code> and blocks further refresh; ensure migration 0001+ and running auth service
          for inserts.
        </p>
        <Button type="button" variant="outline" onClick={() => void refetch()}>
          {isFetching ? "Refreshing…" : "Refresh"}
        </Button>
      </div>

      {isError && error && (
        <InlineError message={getErrorMessage(error)} title="Could not load sessions">
          <Button className="mt-3" variant="outline" type="button" onClick={() => void refetch()}>
            Try again
          </Button>
        </InlineError>
      )}

      {isLoading && <ListSkeleton rows={5} />}

      {!isError && !isLoading && (data?.length ?? 0) === 0 && (
        <EmptyState
          title="No sessions on record"
          description="Sessions appear after users obtain refresh tokens. If the list stays empty, check DB migrations and auth_service refresh_tokens inserts."
        />
      )}

      {!isError && !isLoading && (data?.length ?? 0) > 0 && (
        <DataTable<SessionRow>
          data={data ?? []}
          columns={[
            { key: "user_email", title: "User", render: (row) => row.user_email ?? row.user_id },
            { key: "created_at", title: "Created", render: (row) => formatWhen(row.created_at) },
            { key: "expires_at", title: "Expires", render: (row) => formatWhen(row.expires_at) },
            {
              key: "revoked",
              title: "Revoked",
              render: (row) => (row.revoked ? "Yes" : "No"),
            },
            {
              key: "is_active",
              title: "Active",
              render: (row) => (row.is_active ? "Yes" : "No"),
            },
            {
              key: "id",
              title: "Actions",
              render: (row) => (
                <Button
                  type="button"
                  variant="outline"
                  disabled={!row.is_active || revokeM.isPending}
                  onClick={async () => {
                    if (!row.is_active) return;
                    if (!window.confirm("Revoke this session? The user must sign in again.")) return;
                    try {
                      await revokeM.mutateAsync(row.id);
                    } catch {
                      // api-error is surfaced by axios; could add toast
                    }
                  }}
                >
                  {revokeM.isPending ? "…" : "Revoke"}
                </Button>
              ),
            },
          ]}
        />
      )}

      {revokeM.isError && <p className="text-sm text-red-600">{getErrorMessage(revokeM.error)}</p>}
    </div>
  );
}
