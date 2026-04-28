import { useQuery } from "@tanstack/react-query";

import { fetchRbac } from "@/features/rbac/rbac-api";

export const rbacQueryKey = ["admin", "rbac"] as const;

export function useRbacQuery() {
  return useQuery({
    queryKey: rbacQueryKey,
    queryFn: fetchRbac,
    staleTime: 15_000,
  });
}
