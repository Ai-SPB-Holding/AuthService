import { apiClient } from "@/shared/api/http-client";
import { endpoints } from "@/shared/api/endpoints";
import type { AdminSessionInfo, ServiceSettings, SettingsUpdatePayload, SettingsUpdateResult } from "@/shared/types/settings";

export async function fetchAdminSession() {
  const { data } = await apiClient.get<AdminSessionInfo>(endpoints.admin.session);
  return data;
}

export async function fetchServiceSettings() {
  const { data } = await apiClient.get<ServiceSettings>(endpoints.admin.settings);
  return data;
}

export async function updateServiceSettings(payload: SettingsUpdatePayload) {
  const { data } = await apiClient.put<SettingsUpdateResult>(endpoints.admin.settings, payload);
  return data;
}
