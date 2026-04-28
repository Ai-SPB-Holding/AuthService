import { useQuery } from "@tanstack/react-query";

import { listAuditLogs } from "@/features/audit/audit-api";
import { isAppApiError } from "@/shared/api/api-error";

export const auditQueryKey = (limit: number) => ["admin", "audit", { limit }] as const;

export function useAuditQuery(limit = 100) {
  return useQuery({
    queryKey: auditQueryKey(limit),
    queryFn: () => listAuditLogs(limit),
    staleTime: 10_000,
    retry: (count, err) => {
      if (isAppApiError(err) && (err.httpStatus === 404 || err.httpStatus === 405)) {
        return false;
      }
      return count < 2;
    },
  });
}
