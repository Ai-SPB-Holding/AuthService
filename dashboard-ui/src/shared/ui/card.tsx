import type { PropsWithChildren } from "react";

import { cn } from "@/shared/lib/cn";

export function Card({ children, className }: PropsWithChildren<{ className?: string }>) {
  return (
    <div
      className={cn(
        "rounded-xl border border-slate-200/90 bg-white/90 p-4 shadow-[0_10px_30px_-22px_rgba(15,23,42,0.5)] backdrop-blur-sm dark:border-slate-800/80 dark:bg-slate-900/85 dark:shadow-[0_10px_30px_-18px_rgba(2,6,23,0.9)]",
        className,
      )}
    >
      {children}
    </div>
  );
}
