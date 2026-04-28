import type { ReactNode } from "react";

type Props = { title?: string; message: string; children?: ReactNode };

export function InlineError({ title = "Something went wrong", message, children }: Props) {
  return (
    <div
      className="rounded-lg border border-red-200 bg-red-50/90 px-4 py-3 text-sm text-red-900 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-100"
      role="alert"
    >
      <p className="font-medium">{title}</p>
      <p className="mt-1 text-red-800/90 dark:text-red-200/90">{message}</p>
      {children}
    </div>
  );
}

export function EmptyState({ title, description }: { title: string; description?: string }) {
  return (
    <div
      className="rounded-lg border border-dashed border-slate-200 bg-slate-50/50 px-6 py-10 text-center dark:border-slate-700 dark:bg-slate-900/20"
      role="status"
    >
      <p className="text-sm font-medium text-slate-800 dark:text-slate-200">{title}</p>
      {description && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{description}</p>}
    </div>
  );
}

export function ListSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2" aria-hidden="true" role="presentation">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="h-9 animate-pulse rounded-md bg-slate-200/80 dark:bg-slate-800/80" />
      ))}
    </div>
  );
}
