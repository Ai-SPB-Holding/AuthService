import axios from "axios";

import { env } from "@/shared/config/env";

/**
 * Unauthenticated client for /auth/* — no interceptors (avoids import cycle with `http-client` + `auth-store`).
 */
export const authHttp = axios.create({
  baseURL: env.apiBaseUrl,
  withCredentials: true,
  timeout: 15_000,
  headers: {
    "Content-Type": "application/json",
  },
});
