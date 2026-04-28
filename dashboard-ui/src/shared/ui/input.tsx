import type { InputHTMLAttributes } from "react";

import { cn } from "@/shared/lib/cn";

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cn(
        "w-full rounded-md border border-slate-300/90 bg-white/95 px-3 py-2 text-sm outline-none ring-offset-1 transition focus:border-rose-500 focus:ring-2 focus:ring-rose-500/40 dark:border-slate-700 dark:bg-slate-900/90",
        props.className,
      )}
    />
  );
}
