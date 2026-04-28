import { useState } from "react";

import { useAuditQuery } from "@/features/audit/use-audit-query";
import { getErrorMessage } from "@/shared/api/api-error";
import { Button } from "@/shared/ui/button";
import { DataTable } from "@/shared/ui/table";
import { Input } from "@/shared/ui/input";
import { EmptyState, InlineError, ListSkeleton } from "@/shared/ui/status-blocks";
import type { AuditListItem } from "@/features/audit/audit-api";

function formatDetails(d: unknown): string {
  if (d == null) return "—";
  if (typeof d === "string") return d;
  try {
    return JSON.stringify(d);
  } catch {
    return String(d);
  }
}

function formatWhen(iso: string) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function AuditPage() {
  const [limitStr, setLimitStr] = useState("100");
  const limit = Math.min(500, Math.max(1, Number.parseInt(limitStr, 10) || 100));
  const { data, isLoading, error, isError, refetch } = useAuditQuery(limit);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Combined authentication events and admin API actions for your tenant. Requires database migrations 0002 (auth) and 0003 (admin audit).
        </p>
        <div className="flex w-full max-w-xs items-end gap-2">
          <div className="flex-1">
            <label className="mb-1 block text-xs text-slate-500" htmlFor="audit-limit">
              Max rows
            </label>
            <Input
              id="audit-limit"
              type="number"
              min={1}
              max={500}
              value={limitStr}
              onChange={(e) => setLimitStr(e.target.value)}
            />
          </div>
          <Button type="button" variant="outline" onClick={() => void refetch()}>
            Refresh
          </Button>
        </div>
      </div>

      {isError && error && (
        <InlineError message={getErrorMessage(error)} title="Could not load audit log">
          <Button className="mt-3" variant="outline" type="button" onClick={() => void refetch()}>
            Try again
          </Button>
        </InlineError>
      )}

      {isLoading && <ListSkeleton rows={5} />}

      {!isError && !isLoading && (data?.length ?? 0) === 0 && (
        <EmptyState
          title="No audit entries"
          description="Nothing to show yet, or the audit tables are not deployed. See migration 0003 for the admin audit log."
        />
      )}

      {!isError && !isLoading && (data?.length ?? 0) > 0 && (
        <DataTable<AuditListItem>
          data={data ?? []}
          columns={[
            {
              key: "occurred_at",
              title: "Time",
              render: (row) => <span className="whitespace-nowrap">{formatWhen(row.occurred_at)}</span>,
            },
            { key: "source", title: "Source" },
            { key: "action", title: "Action" },
            {
              key: "user_id",
              title: "User / subject",
              render: (row) => row.user_id ?? "—",
            },
            {
              key: "success",
              title: "OK",
              render: (row) => (row.success == null ? "—" : row.success ? "Yes" : "No"),
            },
            { key: "target", title: "Target", render: (row) => row.target ?? "—" },
            {
              key: "details",
              title: "Details",
              render: (row) => <span className="max-w-xs font-mono text-xs break-all">{formatDetails(row.details)}</span>,
            },
          ]}
        />
      )}
    </div>
  );
}
