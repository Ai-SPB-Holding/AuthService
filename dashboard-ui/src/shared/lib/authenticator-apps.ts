/** TOTP (RFC 6238) is the same for all; only onboarding differs. */
export const AUTHENTICATOR_APP_OPTIONS = [
  { id: "google", label: "Google Authenticator" },
  { id: "microsoft", label: "Microsoft Authenticator" },
  { id: "authy", label: "Authy" },
  { id: "other", label: "Other (any TOTP app)" },
] as const;

export type AuthenticatorAppId = (typeof AUTHENTICATOR_APP_OPTIONS)[number]["id"];

const STEPS: Record<AuthenticatorAppId, string> = {
  google:
    "Open Google Authenticator → + → Scan a QR code (if we show one) or Enter a setup key → paste the secret or otpauth string below, then use the 6-digit code.",
  microsoft:
    "Open Microsoft Authenticator → + → Add work or school (or personal) → enter the setup key or scan from your device, then use the 6-digit code shown for this account.",
  authy: "Open Authy → + → Enter key manually using the base32 secret from below if needed, then use the 6-digit token.",
  other: "In any TOTP app (1Password, Bitwarden, etc.), add an account from the otpauth link or the base32 secret, then enter the current 6-digit code.",
};

export function getAuthenticatorHelp(id: AuthenticatorAppId): string {
  return STEPS[id] ?? STEPS.other;
}
