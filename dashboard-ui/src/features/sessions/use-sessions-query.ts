import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { listSessions, revokeSession } from "@/features/sessions/sessions-api";
import { isAppApiError } from "@/shared/api/api-error";

export const sessionsQueryKey = ["admin", "sessions", "list"] as const;

export function useSessionsQuery() {
  return useQuery({
    queryKey: sessionsQueryKey,
    queryFn: listSessions,
    staleTime: 10_000,
    refetchInterval: 30_000,
    retry: (count, err) => {
      if (isAppApiError(err) && (err.httpStatus === 404 || err.httpStatus === 405)) {
        return false;
      }
      return count < 2;
    },
  });
}

export function useRevokeSessionMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => revokeSession(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: sessionsQueryKey });
    },
  });
}
