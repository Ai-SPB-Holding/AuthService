import { memo } from "react";

import type { User, UserListOrder, UserListSort } from "@/shared/types/user";
import { DataTable } from "@/shared/ui/table";
import { Button } from "@/shared/ui/button";

function formatRegistered(iso: string | undefined) {
  if (iso == null || iso === "") return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "short",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}

function sortIndicator(active: boolean, order: UserListOrder) {
  if (!active) return "↕";
  return order === "asc" ? "↑" : "↓";
}

function UsersTableComponent({
  users,
  onEdit,
  sort,
  order,
  onColumnSort,
}: {
  users: User[];
  onEdit: (user: User) => void;
  sort: UserListSort;
  order: UserListOrder;
  onColumnSort: (key: UserListSort) => void;
}) {
  return (
    <DataTable
      data={users}
      columns={[
        {
          key: "registration_source",
          title: "Source",
          titleContent: (
            <button
              type="button"
              className="inline-flex items-center gap-1 font-medium text-slate-600 hover:text-slate-900 dark:text-slate-200 dark:hover:text-white"
              onClick={() => onColumnSort("registration_source")}
            >
              Source {sortIndicator(sort === "registration_source", order)}
            </button>
          ),
          render: (row) => (
            <span className="font-mono text-xs" title="registration_source at signup">
              {row.registration_source || "—"}
            </span>
          ),
        },
        {
          key: "email",
          title: "Email",
          titleContent: (
            <button
              type="button"
              className="inline-flex items-center gap-1 font-medium text-slate-600 hover:text-slate-900 dark:text-slate-200 dark:hover:text-white"
              onClick={() => onColumnSort("email")}
            >
              Email {sortIndicator(sort === "email", order)}
            </button>
          ),
        },
        {
          key: "created_at",
          title: "Registered",
          titleContent: (
            <button
              type="button"
              className="inline-flex items-center gap-1 font-medium text-slate-600 hover:text-slate-900 dark:text-slate-200 dark:hover:text-white"
              onClick={() => onColumnSort("created_at")}
            >
              Registered {sortIndicator(sort === "created_at", order)}
            </button>
          ),
          render: (row) => formatRegistered(row.created_at),
        },
        { key: "tenant_id", title: "Tenant" },
        { key: "is_active", title: "Active", render: (row) => (row.is_active ? "Yes" : "No") },
        {
          key: "email_verified",
          title: "Email OK",
          render: (row) => (row.email_verified ? "Yes" : "No"),
        },
        {
          key: "is_locked",
          title: "Locked",
          render: (row) => (row.is_locked ? "Yes" : "No"),
        },
        {
          key: "actions",
          title: "Actions",
          render: (row) => (
            <Button variant="outline" type="button" onClick={() => onEdit(row)}>
              Edit
            </Button>
          ),
        },
      ]}
    />
  );
}

export const UsersTable = memo(UsersTableComponent);
