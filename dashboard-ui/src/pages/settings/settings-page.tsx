import { useMemo, useState } from "react";
import { useForm } from "react-hook-form";

import { useServiceSettingsQuery, useUpdateServiceSettings } from "@/features/settings/use-settings-query";
import { useAuthStore } from "@/features/auth/auth-store";
import { getErrorMessage } from "@/shared/api/api-error";
import { Button } from "@/shared/ui/button";
import { Card } from "@/shared/ui/card";
import { Input } from "@/shared/ui/input";
import { InlineError } from "@/shared/ui/status-blocks";
import type { SettingsUpdatePayload } from "@/shared/types/settings";

type FormValues = {
  require_login_2fa: boolean;
  client_mfa_enforce: boolean;
  api_domain: string;
  private_key_pem: string;
  public_key_pem: string;
  cookie_secret: string;
  totp_encryption_key_b64: string;
  totp_code: string;
};

export function SettingsPage() {
  const accessLevel = useAuthStore((s) => s.accessLevel);
  const canEditGlobals = accessLevel === "admin";

  const { data, isLoading, isError, error, refetch } = useServiceSettingsQuery(true);
  const updateMutation = useUpdateServiceSettings();
  const [savedBanner, setSavedBanner] = useState<string | null>(null);

  const defaults = useMemo<FormValues>(
    () => ({
      require_login_2fa: data?.require_login_2fa ?? false,
      client_mfa_enforce: data?.client_mfa_enforce ?? true,
      api_domain: data?.api_domain ?? "",
      private_key_pem: "",
      public_key_pem: "",
      cookie_secret: "",
      totp_encryption_key_b64: "",
      totp_code: "",
    }),
    [data],
  );

  const form = useForm<FormValues>({ values: defaults });

  async function onSubmit(values: FormValues) {
    setSavedBanner(null);
    const payload: SettingsUpdatePayload = {};

    if (canEditGlobals) {
      if (values.require_login_2fa !== data?.require_login_2fa) {
        payload.require_login_2fa = values.require_login_2fa;
      }
      if (values.client_mfa_enforce !== data?.client_mfa_enforce) {
        payload.client_mfa_enforce = values.client_mfa_enforce;
      }
    }

    const apiTrim = values.api_domain.trim();
    if (apiTrim && apiTrim !== (data?.api_domain ?? "")) {
      payload.api_domain = apiTrim;
    }
    if (values.private_key_pem.trim()) {
      payload.private_key_pem = values.private_key_pem.trim();
    }
    if (values.public_key_pem.trim()) {
      payload.public_key_pem = values.public_key_pem.trim();
    }
    if (values.cookie_secret.trim()) {
      payload.cookie_secret = values.cookie_secret.trim();
    }
    if (values.totp_encryption_key_b64.trim()) {
      payload.totp_encryption_key_b64 = values.totp_encryption_key_b64.trim();
    }

    const sensitive =
      !!payload.api_domain ||
      !!payload.private_key_pem ||
      !!payload.public_key_pem ||
      !!payload.cookie_secret ||
      !!payload.totp_encryption_key_b64;
    if (sensitive && values.totp_code.trim()) {
      payload.totp_code = values.totp_code.trim();
    }

    try {
      const res = await updateMutation.mutateAsync(payload);
      form.reset({
        ...values,
        private_key_pem: "",
        public_key_pem: "",
        cookie_secret: "",
        totp_encryption_key_b64: "",
        totp_code: "",
      });
      if (res.restart_required) {
        setSavedBanner("Saved. Restart the auth-service process to apply `.env` changes.");
      } else {
        setSavedBanner("Saved.");
      }
      await refetch();
    } catch (e) {
      form.setError("root", { message: getErrorMessage(e) });
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Service settings</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Updates are written to <code className="text-xs">{data?.env_file_path ?? ".env"}</code>. Sensitive field changes may require a
          Google Authenticator code when 2FA is enabled.
        </p>
        {!canEditGlobals && (
          <p className="mt-2 text-sm text-amber-800 dark:text-amber-200/90">
            You are connected as an OAuth client delegate: only security-related keys below are available; policy toggles are restricted to
            admins.
          </p>
        )}
      </div>

      {isError && (
        <InlineError title="Could not load settings" message={getErrorMessage(error)}>
          <Button className="mt-3" type="button" variant="outline" onClick={() => void refetch()}>
            Retry
          </Button>
        </InlineError>
      )}

      {isLoading && !isError && (
        <p className="text-sm text-slate-500" role="status">
          Loading settings…
        </p>
      )}

      {savedBanner && (
        <div
          className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-900 dark:border-emerald-900/50 dark:bg-emerald-950/40 dark:text-emerald-100"
          role="status"
        >
          {savedBanner}
        </div>
      )}

      {!isError && data && (
        <form className="space-y-6" onSubmit={form.handleSubmit(onSubmit)} noValidate>
          {form.formState.errors.root?.message && (
            <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200" role="alert">
              {form.formState.errors.root.message}
            </p>
          )}

          <Card className="space-y-4 p-4">
            <h3 className="text-sm font-medium">Policy</h3>
            <label className="flex cursor-pointer items-center gap-2 text-sm">
              <input type="checkbox" disabled={!canEditGlobals} className="rounded border-slate-300" {...form.register("require_login_2fa")} />
              Require TOTP (Google Authenticator) for every password login <span className="text-slate-500">(AUTH__REQUIRE_LOGIN_2FA)</span>
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-sm">
              <input type="checkbox" disabled={!canEditGlobals} className="rounded border-slate-300" {...form.register("client_mfa_enforce")} />
              Enforce per-client MFA policy on login / token / authorize <span className="text-slate-500">(OIDC__CLIENT_MFA_ENFORCE)</span>
            </label>
          </Card>

          <Card className="space-y-4 p-4">
            <h3 className="text-sm font-medium">Public URL / issuer</h3>
            <Input placeholder="https://auth.example.com" {...form.register("api_domain")} />
            <p className="text-xs text-slate-500">Mapped to SERVER__ISSUER in `.env`. Current: {data.api_domain}</p>
          </Card>

          <Card className="space-y-4 p-4">
            <h3 className="text-sm font-medium">JWT keys (PEM)</h3>
            <p className="text-xs text-slate-500">
              Leave blank to keep existing file values. Set: private {data.jwt_private_key_pem_set ? "yes" : "no"}, public{" "}
              {data.jwt_public_key_pem_set ? "yes" : "no"}
            </p>
            <textarea
              className="border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex min-h-[120px] w-full rounded-md border px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              placeholder="-----BEGIN PRIVATE KEY----- ..."
              {...form.register("private_key_pem")}
            />
            <textarea
              className="border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex min-h-[120px] w-full rounded-md border px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              placeholder="-----BEGIN PUBLIC KEY----- ..."
              {...form.register("public_key_pem")}
            />
          </Card>

          <Card className="space-y-4 p-4">
            <h3 className="text-sm font-medium">Secrets</h3>
            <p className="text-xs text-slate-500">
              Cookie secret set: {data.cookie_secret_set ? "yes" : "no"} · TOTP encryption key set: {data.totp_encryption_key_b64_set ? "yes" : "no"}
            </p>
            <Input type="password" autoComplete="off" placeholder="New AUTH__COOKIE_SECRET (min 16 chars)" {...form.register("cookie_secret")} />
            <Input type="password" autoComplete="off" placeholder="New TOTP__ENCRYPTION_KEY_B64 (32-byte key, base64)" {...form.register("totp_encryption_key_b64")} />
          </Card>

          <Card className="space-y-4 p-4">
            <h3 className="text-sm font-medium">Authenticator code (sensitive changes)</h3>
            <p className="text-xs text-slate-500">
              When 2FA is required, enter your current TOTP code before saving issuer, keys, cookie secret, or TOTP encryption key.
            </p>
            <Input inputMode="numeric" autoComplete="one-time-code" placeholder="6-digit code" {...form.register("totp_code")} />
          </Card>

          <div className="flex gap-2">
            <Button type="submit" disabled={updateMutation.isPending}>
              {updateMutation.isPending ? "Saving…" : "Save to .env"}
            </Button>
            <Button type="button" variant="outline" onClick={() => void refetch()}>
              Reload
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}
