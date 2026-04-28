import { useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { rbacQueryKey, useRbacQuery } from "@/features/rbac/use-rbac-query";
import { useSSE } from "@/hooks/use-sse";
import { getErrorMessage } from "@/shared/api/api-error";
import { Button } from "@/shared/ui/button";
import { Card } from "@/shared/ui/card";
import { DataTable } from "@/shared/ui/table";
import { EmptyState, InlineError, ListSkeleton } from "@/shared/ui/status-blocks";

export function RolesPage() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError, error, refetch, isFetching } = useRbacQuery();

  const onSse = useCallback(
    (ev: MessageEvent<string>) => {
      if (String(ev.data ?? "").length > 0) {
        void queryClient.invalidateQueries({ queryKey: rbacQueryKey });
      }
    },
    [queryClient],
  );

  useSSE(onSse);

  return (
    <div className="space-y-6">
      <p className="text-sm text-slate-500 dark:text-slate-400">
        Roles, permissions, and <strong>role ↔ permission</strong> links for your tenant. Manage assignments via API or database
        (UI editing can be added later).
      </p>
      {isFetching && !isLoading && <p className="text-xs text-slate-500">Refreshing…</p>}

      {isError && (
        <InlineError title="Could not load RBAC" message={getErrorMessage(error)}>
          <Button className="mt-3" type="button" variant="outline" onClick={() => void refetch()}>
            Retry
          </Button>
        </InlineError>
      )}

      {isLoading && !isError && <ListSkeleton rows={6} />}

      {!isError && !isLoading && data && (
        <>
          <section>
            <h2 className="mb-2 text-sm font-semibold text-slate-800 dark:text-slate-200">Roles</h2>
            {data.roles.length === 0 ? (
              <EmptyState title="No roles" description="Create roles with POST /admin/roles" />
            ) : (
              <DataTable
                data={data.roles}
                columns={[
                  { key: "name", title: "Name" },
                  { key: "id", title: "ID" },
                ]}
              />
            )}
          </section>

          <section>
            <h2 className="mb-2 text-sm font-semibold text-slate-800 dark:text-slate-200">Permissions</h2>
            {data.permissions.length === 0 ? (
              <EmptyState title="No permissions" description="Create permissions with POST /admin/permissions" />
            ) : (
              <DataTable
                data={data.permissions}
                columns={[
                  { key: "name", title: "Name" },
                  { key: "id", title: "ID" },
                ]}
              />
            )}
          </section>

          <section>
            <h2 className="mb-2 text-sm font-semibold text-slate-800 dark:text-slate-200">RBAC mapping (role → permission)</h2>
            {data.role_permissions.length === 0 ? (
              <Card className="p-4">
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  No <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">role_permissions</code> rows for this tenant. Assign
                  permissions to roles in the database or extend the API to POST links.
                </p>
              </Card>
            ) : (
              <DataTable
                data={data.role_permissions.map((row) => ({ ...row, id: `${row.role_id}-${row.permission_id}` }))}
                columns={[
                  { key: "role_name", title: "Role" },
                  { key: "permission_name", title: "Permission" },
                  { key: "role_id", title: "Role ID" },
                  { key: "permission_id", title: "Permission ID" },
                ]}
              />
            )}
          </section>
        </>
      )}
    </div>
  );
}
