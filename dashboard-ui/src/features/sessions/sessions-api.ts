import { apiClient } from "@/shared/api/http-client";
import { endpoints } from "@/shared/api/endpoints";

export type SessionRow = {
  id: string;
  user_id: string;
  user_email: string | null;
  created_at: string;
  expires_at: string;
  revoked: boolean;
  is_active: boolean;
};

export async function listSessions() {
  const { data } = await apiClient.get<SessionRow[]>(endpoints.admin.sessions.list);
  return data;
}

export async function revokeSession(id: string) {
  const { data } = await apiClient.post<{ ok: boolean }>(endpoints.admin.sessions.revoke(id));
  return data;
}
