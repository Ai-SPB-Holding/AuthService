import { apiClient } from "@/shared/api/http-client";
import { endpoints } from "@/shared/api/endpoints";
import type { RbacResponse } from "@/shared/types/rbac";

export async function fetchRbac() {
  const { data } = await apiClient.get<RbacResponse>(endpoints.admin.rbac);
  return data;
}
