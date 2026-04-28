import { useQuery } from "@tanstack/react-query";

import { fetchDashboardStats } from "@/features/dashboard/dashboard-api";

export const dashboardStatsKey = ["dashboard", "stats"] as const;

export function useDashboardStats() {
  return useQuery({
    queryKey: dashboardStatsKey,
    queryFn: fetchDashboardStats,
    staleTime: 15_000,
  });
}
