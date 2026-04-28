import { apiClient } from "@/shared/api/http-client";
import { endpoints } from "@/shared/api/endpoints";
import type { User, UserListOrder, UserListSort } from "@/shared/types/user";

export async function listUsers(
  search: string,
  sort: UserListSort = "created_at",
  order: UserListOrder = "desc",
) {
  const { data } = await apiClient.get<User[]>(endpoints.admin.users.list, {
    params: {
      ...(search.trim() ? { q: search.trim() } : {}),
      sort,
      order,
    },
  });
  return data;
}

export async function generateTenantId() {
  const { data } = await apiClient.get<{ tenant_id: string }>(endpoints.admin.tenantIds.generate);
  return data.tenant_id;
}

export async function getUser(id: string) {
  const { data } = await apiClient.get<User>(endpoints.admin.users.detail(id));
  return data;
}

export async function createUser(payload: {
  tenant_id: string;
  email: string;
  password: string;
  registration_source?: string;
}) {
  const { data } = await apiClient.post<{ id: string }>(endpoints.admin.users.create, {
    tenant_id: payload.tenant_id,
    email: payload.email,
    password: payload.password,
    registration_source: (payload.registration_source?.trim() || "dashboard"),
  });
  return data;
}

export type PatchUserPayload = {
  email?: string;
  tenant_id?: string;
  is_locked?: boolean;
  is_active?: boolean;
};

export async function patchUser(id: string, body: PatchUserPayload) {
  const { data } = await apiClient.patch<User>(endpoints.admin.users.patch(id), body);
  return data;
}

export async function deleteUser(id: string) {
  await apiClient.delete(endpoints.admin.users.remove(id));
}

export async function sendVerificationEmail(id: string) {
  await apiClient.post(endpoints.admin.users.sendVerificationEmail(id));
}

export async function verifyEmailAdmin(id: string) {
  await apiClient.post(endpoints.admin.users.verifyEmail(id));
}

export async function resetEmailVerification(id: string) {
  await apiClient.post(endpoints.admin.users.resetEmailVerification(id));
}
