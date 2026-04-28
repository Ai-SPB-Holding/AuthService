import type { AccessTokenPayload } from "@/shared/types/auth";

/**
 * Decodes access token payload (no signature verification; server validates the token).
 */
export function parseAccessTokenPayload(token: string): AccessTokenPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const payloadB64 = parts[1];
    if (payloadB64 == null) return null;
    const json = atob(base64UrlToBase64(payloadB64));
    const data = JSON.parse(json) as unknown;
    if (!isAccessTokenPayload(data)) return null;
    return data;
  } catch {
    return null;
  }
}

function base64UrlToBase64(b64url: string): string {
  let s = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "====".slice(0, 4 - pad);
  return s;
}

function isAccessTokenPayload(x: unknown): x is AccessTokenPayload {
  if (typeof x !== "object" || x === null) return false;
  const o = x as Record<string, unknown>;
  return typeof o.sub === "string" && Array.isArray(o.roles);
}
