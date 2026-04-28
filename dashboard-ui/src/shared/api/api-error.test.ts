import { describe, expect, it } from "vitest";
import { AxiosError, type InternalAxiosRequestConfig } from "axios";

import { AppApiError, getErrorMessage, isAppApiError, parseApiError, parseAxiosError } from "@/shared/api/api-error";

describe("parseApiError", () => {
  it("wraps AppApiError", () => {
    const a = new AppApiError({ message: "m", httpStatus: 400, raw: null });
    expect(parseApiError(a)).toBe(a);
  });

  it("normalizes axios error with backend { error: string }", () => {
    const cfg = { url: "/x" } as InternalAxiosRequestConfig;
    const err = new AxiosError(
      "Request failed",
      "ERR_BAD_REQUEST",
      cfg,
      {},
      {
        status: 400,
        data: { error: "Invalid password" },
        headers: {},
        statusText: "Bad Request",
        config: cfg,
      },
    );
    const p = parseAxiosError(err);
    expect(p).toBeInstanceOf(AppApiError);
    expect(p.message).toBe("Invalid password");
    expect(p.httpStatus).toBe(400);
  });
});

describe("getErrorMessage", () => {
  it("uses AppApiError message", () => {
    const e = new AppApiError({ message: "x", httpStatus: 0, raw: null });
    expect(getErrorMessage(e)).toBe("x");
  });
});

describe("isAppApiError", () => {
  it("is true for AppApiError", () => {
    expect(isAppApiError(new AppApiError({ message: "m", httpStatus: 0, raw: null }))).toBe(true);
  });
  it("is false for Error", () => {
    expect(isAppApiError(new Error("e"))).toBe(false);
  });
});
