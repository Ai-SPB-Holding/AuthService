import { useEffect, useRef } from "react";

import { env } from "@/shared/config/env";
import { useFeatureFlags } from "@/features/feature-flags/flags-store";

const MAX_DELAY_MS = 30_000;
const INITIAL_DELAY_MS = 1000;

export function useSSE(onMessage: (payload: MessageEvent<string>) => void) {
  const liveUpdates = useFeatureFlags((s) => s.liveUpdates);
  const onMessageRef = useRef(onMessage);

  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);

  useEffect(() => {
    if (!liveUpdates) return;

    let eventSource: EventSource | null = null;
    let cancelled = false;
    let attempt = 0;
    let retryTimer: number | null = null;

    const open = () => {
      if (cancelled) return;
      try {
        eventSource = new EventSource(env.sseUrl, { withCredentials: true });
      } catch {
        scheduleRetry();
        return;
      }

      eventSource.onmessage = (ev) => onMessageRef.current(ev);

      eventSource.onerror = () => {
        eventSource?.close();
        eventSource = null;
        scheduleRetry();
      };

      eventSource.onopen = () => {
        attempt = 0;
      };
    };

    const scheduleRetry = () => {
      if (cancelled) return;
      const delay = Math.min(INITIAL_DELAY_MS * 2 ** attempt, MAX_DELAY_MS);
      attempt += 1;
      retryTimer = window.setTimeout(() => {
        open();
      }, delay);
    };

    open();

    return () => {
      cancelled = true;
      if (retryTimer !== null) window.clearTimeout(retryTimer);
      eventSource?.close();
    };
  }, [liveUpdates]);
}
