import { describe, expect, it } from "vitest";

import { parseAccessTokenPayload } from "@/shared/lib/jwt";

function b64UrlEncodeJson(obj: object): string {
  const json = JSON.stringify(obj);
  const b64 = btoa(json);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("parseAccessTokenPayload", () => {
  it("extracts roles from access token payload", () => {
    const payload = {
      sub: "00000000-0000-0000-0000-000000000000",
      exp: 9999999999,
      iss: "https://issuer",
      aud: "auth-service",
      roles: ["user", "admin"],
      permissions: ["read"],
      tenant_id: "00000000-0000-0000-0000-000000000001",
    };
    const token = `e30.${b64UrlEncodeJson(payload)}.sig`;
    const result = parseAccessTokenPayload(token);
    expect(result?.sub).toBe(payload.sub);
    expect(result?.roles).toEqual(["user", "admin"]);
    expect(result?.tenant_id).toBe(payload.tenant_id);
  });

  it("returns null for malformed token", () => {
    expect(parseAccessTokenPayload("not-a-jwt")).toBeNull();
  });
});
