/**
 * In-memory session only (no refresh token in localStorage/sessionStorage) to limit XSS impact.
 * Survives SPA navigation; full reload requires a new login.
 */
let memRefresh: string | null = null;
let memAudience: string | null = null;

export function readRefreshTokenFromStorage(): string | null {
  return memRefresh;
}

export function readAudienceFromStorage(): string | null {
  return memAudience;
}

export function writeAuthSession(refreshToken: string | null, audience: string | null) {
  memRefresh = refreshToken;
  memAudience = audience;
}

export function clearAuthSession() {
  memRefresh = null;
  memAudience = null;
}
