import { useAuthStore } from "./auth-store";

export function useAuth() {
  const accessToken = useAuthStore((s) => s.accessToken);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const isLoading = useAuthStore((s) => s.isLoading);
  const isBootstrapping = useAuthStore((s) => s.isBootstrapping);
  const roles = useAuthStore((s) => s.roles);
  const login = useAuthStore((s) => s.login);
  const refresh = useAuthStore((s) => s.refresh);
  const logout = useAuthStore((s) => s.logout);

  return {
    accessToken,
    isAuthenticated,
    isLoading,
    isBootstrapping,
    roles,
    login,
    refresh,
    logout,
  };
}
