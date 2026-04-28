import axios, { isAxiosError, type InternalAxiosRequestConfig } from "axios";

import { env } from "@/shared/config/env";
import { useAuthStore } from "@/features/auth/auth-store";
import { parseApiError } from "@/shared/api/api-error";

export const apiClient = axios.create({
  baseURL: env.apiBaseUrl,
  withCredentials: true,
  timeout: 15_000,
  headers: {
    "Content-Type": "application/json",
  },
});

let refreshingTokenPromise: Promise<void> | null = null;

function isAuthRefreshPath(config: InternalAxiosRequestConfig): boolean {
  const url = String(config.url ?? "");
  return url.includes("auth/refresh");
}

function isAuthNoRetryPath(config: InternalAxiosRequestConfig): boolean {
  const url = String(config.url ?? "");
  return url.includes("auth/login") || url.includes("auth/register");
}

async function ensureFreshToken() {
  if (!refreshingTokenPromise) {
    refreshingTokenPromise = useAuthStore
      .getState()
      .refresh()
      .finally(() => {
        refreshingTokenPromise = null;
      });
  }

  await refreshingTokenPromise;
}

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (!isAxiosError(error)) {
      return Promise.reject(parseApiError(error));
    }
    if (!error.config) {
      return Promise.reject(parseApiError(error));
    }

    const status = error.response?.status;
    const originalRequest: InternalAxiosRequestConfig = error.config;

    if (status !== 401) {
      return Promise.reject(parseApiError(error));
    }

    if (isAuthNoRetryPath(originalRequest)) {
      return Promise.reject(parseApiError(error));
    }

    if (isAuthRefreshPath(originalRequest)) {
      await useAuthStore.getState().logout();
      return Promise.reject(parseApiError(error));
    }

    if (originalRequest._authRetry) {
      await useAuthStore.getState().logout();
      return Promise.reject(parseApiError(error));
    }

    originalRequest._authRetry = true;
    try {
      await ensureFreshToken();
      const token = useAuthStore.getState().accessToken;
      if (token) {
        originalRequest.headers = originalRequest.headers ?? {};
        originalRequest.headers.Authorization = `Bearer ${token}`;
      }
      return await apiClient(originalRequest);
    } catch (e) {
      await useAuthStore.getState().logout();
      return Promise.reject(parseApiError(e));
    }
  },
);
