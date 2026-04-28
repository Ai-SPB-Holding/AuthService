import type { ReactNode } from "react";

export type Column<T> = {
  key: keyof T | string;
  title: string;
  /** When set, rendered in the header cell instead of `title` (e.g. sort controls). */
  titleContent?: ReactNode;
  render?: (row: T) => ReactNode;
};

function formatCellValue<T>(row: T, key: Column<T>["key"]): string {
  const v = (row as Record<string, unknown>)[String(key)];
  if (v == null) return "";
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean" || typeof v === "bigint") {
    return String(v);
  }
  if (typeof v === "symbol") return v.description ?? "";
  if (typeof v === "object") {
    return JSON.stringify(v);
  }
  if (typeof v === "function") {
    return "[function]";
  }
  return JSON.stringify(v);
}

export function DataTable<T extends { id: string }>({
  data,
  columns,
  loading,
}: {
  data: T[];
  columns: Column<T>[];
  loading?: boolean;
}) {
  if (loading) {
    return <div className="space-y-3">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-10 animate-pulse rounded bg-slate-200 dark:bg-slate-800" />)}</div>;
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800">
      <table className="min-w-full text-sm">
        <thead className="bg-slate-100 dark:bg-slate-800/70">
          <tr>
            {columns.map((column) => (
              <th key={String(column.key)} className="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-200">
                {column.titleContent ?? column.title}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr key={row.id} className="border-t border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/60">
              {columns.map((column) => (
                <td key={String(column.key)} className="px-4 py-3">
                  {column.render ? column.render(row) : formatCellValue(row, column.key)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
