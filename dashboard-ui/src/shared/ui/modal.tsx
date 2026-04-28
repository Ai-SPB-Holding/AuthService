import { useEffect, useId, useRef, type PropsWithChildren } from "react";
import { createPortal } from "react-dom";

import { Button } from "@/shared/ui/button";

import { cn } from "@/shared/lib/cn";

type ModalProps = PropsWithChildren<{
  title: string;
  onClose: () => void;
  className?: string;
}>;

export function Modal({ title, onClose, children, className }: ModalProps) {
  const labelId = useId();
  const closeRef = useRef<HTMLButtonElement>(null);
  const lastActive = useRef<HTMLElement | null>(null);

  useEffect(() => {
    lastActive.current = document.activeElement as HTMLElement;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();

    return () => {
      document.body.style.overflow = prevOverflow;
      lastActive.current?.focus?.();
    };
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/45 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={labelId}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className={cn(
          "flex max-h-[min(90vh,720px)] w-full max-w-lg flex-col rounded-xl border border-slate-200 bg-white p-4 shadow-lg dark:border-slate-800 dark:bg-slate-900",
          className,
        )}
      >
        <div className="mb-4 flex shrink-0 items-center justify-between gap-2">
          <h3 id={labelId} className="text-lg font-semibold">
            {title}
          </h3>
          <Button ref={closeRef} type="button" variant="ghost" onClick={onClose} aria-label="Close dialog">
            Close
          </Button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain pr-0.5">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
