import { apiClient } from "@/shared/api/http-client";
import { endpoints } from "@/shared/api/endpoints";
import type { OAuthClientRow } from "@/shared/types/oauth-client";

export type MfaPolicy = "off" | "optional" | "required";

export type ClientWritePayload = {
  client_id?: string;
  client_type?: "public" | "confidential";
  redirect_uri?: string;
  redirect_urls?: string[];
  scopes?: string;
  allow_user_registration?: boolean;
  mfa_policy?: MfaPolicy;
  allow_client_totp_enrollment?: boolean;
  user_schema?: Array<{
    field_name: string;
    field_type: string;
    is_auth: boolean;
    is_required: boolean;
  }>;
  embedded_login_enabled?: boolean;
  embedded_token_audience?: string;
  embedded_parent_origins?: string[];
  embedded_protocol_v2?: boolean;
  embedded_ui_theme?: object;
};

export type CreateClientResponse = {
  id: string;
  ok: boolean;
  client_id: string;
  client_type: "public" | "confidential";
  allow_user_registration: boolean;
  client_secret?: string;
  message?: string;
};

export async function listClients() {
  const { data } = await apiClient.get<OAuthClientRow[]>(endpoints.admin.clients.list);
  return data;
}

export async function getClient(id: string) {
  const { data } = await apiClient.get<OAuthClientRow>(endpoints.admin.clients.detail(id));
  return data;
}

export async function createClient(payload: ClientWritePayload) {
  const { data } = await apiClient.post<CreateClientResponse>(endpoints.admin.clients.create, payload);
  return data;
}

export async function updateClient(id: string, payload: ClientWritePayload) {
  const { data } = await apiClient.put<{ ok: boolean }>(endpoints.admin.clients.detail(id), payload);
  return data;
}

export async function deleteClient(id: string) {
  const { data } = await apiClient.delete<{ ok: boolean }>(endpoints.admin.clients.detail(id));
  return data;
}

export async function generateClientId() {
  const { data } = await apiClient.post<{ client_id: string }>(endpoints.admin.clients.generateId);
  return data;
}

export type AdminUserClient2faStatus = { client_totp_enabled: boolean };

export async function getAdminUserClient2faStatus(clientRowId: string, userId: string) {
  const { data } = await apiClient.get<AdminUserClient2faStatus>(
    endpoints.admin.clients.userClient2fa(clientRowId, userId),
  );
  return data;
}

export type Client2faSetupResponse = { otpauth_url: string; secret_base32: string };

export async function adminUserClient2faSetup(clientRowId: string, userId: string) {
  const { data } = await apiClient.post<Client2faSetupResponse>(
    `${endpoints.admin.clients.userClient2fa(clientRowId, userId)}/setup`,
  );
  return data;
}

export async function adminUserClient2faVerify(clientRowId: string, userId: string, code: string) {
  const { data } = await apiClient.post<{ ok: boolean; client_totp_enabled: boolean }>(
    `${endpoints.admin.clients.userClient2fa(clientRowId, userId)}/verify`,
    { code },
  );
  return data;
}

export async function adminUserClient2faDisable(clientRowId: string, userId: string, code: string) {
  const { data } = await apiClient.post<{ ok: boolean; client_totp_enabled: boolean }>(
    `${endpoints.admin.clients.userClient2fa(clientRowId, userId)}/disable`,
    { code },
  );
  return data;
}
