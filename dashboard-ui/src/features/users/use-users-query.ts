import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  createUser,
  deleteUser,
  generateTenantId,
  patchUser,
  resetEmailVerification,
  sendVerificationEmail,
  listUsers,
  verifyEmailAdmin,
  type PatchUserPayload,
} from "@/features/users/users-api";
import { isAppApiError } from "@/shared/api/api-error";
import type { UserListOrder, UserListSort } from "@/shared/types/user";

export const usersQueryKey = (search: string, sort: UserListSort, order: UserListOrder) =>
  ["users", "list", { search, sort, order }] as const;

const usersListKeyPrefix = ["users", "list"] as const;

export function useUsersQuery(search: string, sort: UserListSort, order: UserListOrder) {
  return useQuery({
    queryKey: usersQueryKey(search, sort, order),
    queryFn: () => listUsers(search, sort, order),
    staleTime: 15_000,
    retry: (count, err) => {
      if (isAppApiError(err) && (err.httpStatus === 404 || err.httpStatus === 405)) {
        return false;
      }
      return count < 2;
    },
  });
}

function invalidateUserLists(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: usersListKeyPrefix });
}

export function useCreateUserMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: createUser,
    onSuccess: () => invalidateUserLists(queryClient),
  });
}

export function usePatchUserMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: PatchUserPayload }) => patchUser(id, body),
    onSuccess: () => invalidateUserLists(queryClient),
  });
}

export function useDeleteUserMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: deleteUser,
    onSuccess: () => invalidateUserLists(queryClient),
  });
}

export function useSendVerificationEmailMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: sendVerificationEmail,
    onSuccess: () => invalidateUserLists(queryClient),
  });
}

export function useVerifyEmailAdminMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: verifyEmailAdmin,
    onSuccess: () => invalidateUserLists(queryClient),
  });
}

export function useResetEmailVerificationMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: resetEmailVerification,
    onSuccess: () => invalidateUserLists(queryClient),
  });
}

export function useGenerateTenantIdMutation() {
  return useMutation({
    mutationFn: generateTenantId,
  });
}
