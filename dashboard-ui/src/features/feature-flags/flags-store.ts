import { create } from "zustand";

type FeatureFlags = {
  liveUpdates: boolean;
  advancedAudit: boolean;
  setFlag: (key: "liveUpdates" | "advancedAudit", value: boolean) => void;
};

export const useFeatureFlags = create<FeatureFlags>((set) => ({
  liveUpdates: true,
  advancedAudit: false,
  setFlag: (key, value) => set((state) => ({ ...state, [key]: value })),
}));
