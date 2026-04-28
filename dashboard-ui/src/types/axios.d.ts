import "axios";

declare module "axios" {
  interface InternalAxiosRequestConfig {
    /** Prevents refresh retry loop for auth endpoints. */
    _authRetry?: boolean;
  }
}
