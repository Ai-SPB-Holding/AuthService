import { apiClient } from "@/shared/api/http-client";
import { endpoints } from "@/shared/api/endpoints";
import type { DashboardStats } from "@/shared/types/dashboard";

export async function fetchDashboardStats() {
  const { data } = await apiClient.get<DashboardStats>(endpoints.admin.dashboard.stats);
  return data;
}
