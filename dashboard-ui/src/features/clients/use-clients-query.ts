import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  type ClientWritePayload,
  createClient,
  deleteClient,
  generateClientId,
  listClients,
  updateClient,
} from "@/features/clients/clients-api";
import { isAppApiError } from "@/shared/api/api-error";

export const clientsQueryKey = ["admin", "clients", "list"] as const;

export function useClientsQuery() {
  return useQuery({
    queryKey: clientsQueryKey,
    queryFn: listClients,
    staleTime: 15_000,
    retry: (count, err) => {
      if (isAppApiError(err) && (err.httpStatus === 404 || err.httpStatus === 405)) {
        return false;
      }
      return count < 2;
    },
  });
}

export function useCreateClientMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ClientWritePayload) => createClient(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: clientsQueryKey });
    },
  });
}

export function useUpdateClientMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: ClientWritePayload }) => updateClient(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: clientsQueryKey });
    },
  });
}

export function useDeleteClientMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteClient(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: clientsQueryKey });
    },
  });
}

export function useGenerateClientIdMutation() {
  return useMutation({
    mutationFn: generateClientId,
  });
}
