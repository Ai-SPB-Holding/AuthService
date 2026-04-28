import { isAxiosError, type AxiosError } from "axios";

export type ApiErrorDetails = {
  message: string;
  httpStatus: number;
  code?: string;
  requestId?: string;
  raw: unknown;
};

/**
 * Normalized app error for UI (toasts, form errors, empty states).
 */
export class AppApiError extends Error {
  readonly httpStatus: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly raw: unknown;

  constructor(details: ApiErrorDetails) {
    super(details.message);
    this.name = "AppApiError";
    this.httpStatus = details.httpStatus;
    this.code = details.code;
    this.requestId = details.requestId;
    this.raw = details.raw;
  }
}

type BackendErrorBody = {
  error?: string;
  message?: string;
  code?: string;
  details?: string;
};

function readBackendMessage(body: unknown): string {
  if (body && typeof body === "object" && "error" in body) {
    const b = body as BackendErrorBody;
    if (typeof b.error === "string" && b.error.length > 0) return b.error;
    if (typeof b.message === "string" && b.message.length > 0) return b.message;
  }
  if (typeof body === "string" && body.length > 0) return body;
  return "Request failed";
}

export function isAppApiError(e: unknown): e is AppApiError {
  return e instanceof AppApiError;
}

export function parseApiError(e: unknown): AppApiError {
  if (isAppApiError(e)) return e;
  if (isAxiosError(e)) {
    return parseAxiosError(e);
  }
  if (e instanceof Error) {
    return new AppApiError({ message: e.message, httpStatus: 0, raw: e });
  }
  return new AppApiError({ message: "Unknown error", httpStatus: 0, raw: e });
}

export function parseAxiosError(err: AxiosError<unknown>): AppApiError {
  const status = err.response?.status ?? 0;
  const data = err.response?.data;
  const message = readBackendMessage(data) || err.message || "Network request failed";
  const code =
    data && typeof data === "object" && "code" in data && typeof (data as BackendErrorBody).code === "string"
      ? (data as BackendErrorBody).code
      : undefined;
  const requestId = err.response?.headers["x-request-id"] ?? err.response?.headers["X-Request-Id"];
  return new AppApiError({
    message,
    httpStatus: status,
    code,
    requestId: typeof requestId === "string" ? requestId : undefined,
    raw: err,
  });
}

export function getErrorMessage(e: unknown): string {
  return parseApiError(e).message;
}
