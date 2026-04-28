import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { fetchServiceSettings, updateServiceSettings } from "@/features/settings/settings-api";
import type { SettingsUpdatePayload } from "@/shared/types/settings";

export const serviceSettingsKey = ["service-settings"] as const;

export function useServiceSettingsQuery(enabled = true) {
  return useQuery({
    queryKey: serviceSettingsKey,
    queryFn: fetchServiceSettings,
    enabled,
  });
}

export function useUpdateServiceSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: SettingsUpdatePayload) => updateServiceSettings(payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: serviceSettingsKey });
    },
  });
}
