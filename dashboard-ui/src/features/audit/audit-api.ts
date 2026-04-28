import { apiClient } from "@/shared/api/http-client";
import { endpoints } from "@/shared/api/endpoints";

export type AuditListItem = {
  id: string;
  occurred_at: string;
  source: string;
  action: string;
  user_id: string | null;
  success: boolean | null;
  target: string | null;
  details: unknown;
};

export async function listAuditLogs(limit = 100) {
  const { data } = await apiClient.get<AuditListItem[]>(endpoints.admin.auditLogs, {
    params: { limit },
  });
  return data;
}
