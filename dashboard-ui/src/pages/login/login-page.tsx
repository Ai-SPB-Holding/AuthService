import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom";
import { z } from "zod";

import { useAuth } from "@/features/auth/use-auth";
import { useAuthStore } from "@/features/auth/auth-store";
import { loginMfaRequest, totpSetupRequest, totpVerifyRequest } from "@/services/auth/auth-api";
import { getErrorMessage } from "@/shared/api/api-error";
import {
  type AuthenticatorAppId,
  AUTHENTICATOR_APP_OPTIONS,
  getAuthenticatorHelp,
} from "@/shared/lib/authenticator-apps";
import { env } from "@/shared/config/env";
import { Button } from "@/shared/ui/button";
import { Card } from "@/shared/ui/card";
import { Input } from "@/shared/ui/input";

const loginSchema = z.object({
  tenant_id: z.string().uuid(),
  email: z.string().email(),
  password: z.string().min(8),
  audience: z.string().min(2),
});

type LoginFormValues = z.infer<typeof loginSchema>;

export function LoginPage() {
  const navigate = useNavigate();
  const { login, isLoading, isAuthenticated, isBootstrapping } = useAuth();
  const finishLoginWithTokens = useAuthStore((s) => s.finishLoginWithTokens);
  const pre = env.loginDevDefaults();

  /** `enroll` = first-time TOTP setup; `mfa` = 6-digit code after password when TOTP already on. */
  const [loginSubView, setLoginSubView] = useState<"none" | "enroll" | "mfa">("none");
  const [enrollmentToken, setEnrollmentToken] = useState<string | null>(null);
  const [enrollAudience, setEnrollAudience] = useState<string | null>(null);
  const [otpauthUrl, setOtpauthUrl] = useState<string | null>(null);
  const [enrollCode, setEnrollCode] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaStepUpToken, setMfaStepUpToken] = useState<string | null>(null);
  const [mfaAudience, setMfaAudience] = useState<string | null>(null);
  const [enrollBusy, setEnrollBusy] = useState(false);
  const [authenticatorApp, setAuthenticatorApp] = useState<AuthenticatorAppId>("google");

  const form = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      tenant_id: pre.tenant,
      email: pre.email,
      password: pre.password,
      audience: pre.audience,
    },
  });
  const rootError = form.formState.errors.root;

  function navigateAfterSession() {
    const { accessLevel } = useAuthStore.getState();
    if (accessLevel === "admin") {
      void navigate("/", { replace: true });
    } else if (accessLevel === "client_settings") {
      void navigate("/settings", { replace: true });
    } else {
      void navigate("/access-denied", { replace: true });
    }
  }

  useEffect(() => {
    if (isBootstrapping || !isAuthenticated) return;
    const { sessionLoaded } = useAuthStore.getState();
    if (!sessionLoaded) return;
    navigateAfterSession();
  }, [isAuthenticated, isBootstrapping, navigate]);

  async function onSubmit(values: LoginFormValues) {
    form.clearErrors("root");
    try {
      const r = await login(values);
      if (r.status === "totp_enrollment") {
        setEnrollBusy(true);
        try {
          const s = await totpSetupRequest(r.enrollmentToken);
          setOtpauthUrl(s.otpauth_url);
          setEnrollmentToken(r.enrollmentToken);
          setEnrollAudience(r.audience);
          setLoginSubView("enroll");
          setEnrollCode("");
        } finally {
          setEnrollBusy(false);
        }
        return;
      }
      if (r.status === "mfa") {
        setMfaStepUpToken(r.stepUpToken);
        setMfaAudience(r.audience);
        setMfaCode("");
        setLoginSubView("mfa");
        return;
      }
      navigateAfterSession();
    } catch (e) {
      form.setError("root", { message: getErrorMessage(e) });
    }
  }

  async function onCompleteTotpEnroll() {
    if (!enrollmentToken || !enrollAudience) {
      return;
    }
    const code = enrollCode.trim();
    if (code.length < 6) {
      form.setError("root", { message: "Enter the 6-digit code from your authenticator app." });
      return;
    }
    form.clearErrors("root");
    setEnrollBusy(true);
    try {
      const data = await totpVerifyRequest(enrollmentToken, code);
      await finishLoginWithTokens(
        {
          access_token: data.access_token,
          refresh_token: data.refresh_token,
          token_type: data.token_type,
          expires_in: data.expires_in,
        },
        enrollAudience,
      );
      setLoginSubView("none");
      setEnrollmentToken(null);
      setEnrollAudience(null);
      setOtpauthUrl(null);
      navigateAfterSession();
    } catch (e) {
      form.setError("root", { message: getErrorMessage(e) });
    } finally {
      setEnrollBusy(false);
    }
  }

  async function onCompleteMfaLogin() {
    if (!mfaStepUpToken || !mfaAudience) {
      return;
    }
    const code = mfaCode.trim();
    if (code.length < 6) {
      form.setError("root", { message: "Enter the 6-digit code from your authenticator app." });
      return;
    }
    form.clearErrors("root");
    setEnrollBusy(true);
    try {
      const data = await loginMfaRequest(mfaStepUpToken, code);
      await finishLoginWithTokens(data, mfaAudience);
      setLoginSubView("none");
      setMfaStepUpToken(null);
      setMfaAudience(null);
      setMfaCode("");
      navigateAfterSession();
    } catch (e) {
      form.setError("root", { message: getErrorMessage(e) });
    } finally {
      setEnrollBusy(false);
    }
  }

  function onCancelEnroll() {
    setLoginSubView("none");
    setEnrollmentToken(null);
    setEnrollAudience(null);
    setOtpauthUrl(null);
    setEnrollCode("");
    form.clearErrors("root");
  }

  function onCancelMfa() {
    setLoginSubView("none");
    setMfaStepUpToken(null);
    setMfaAudience(null);
    setMfaCode("");
    form.clearErrors("root");
  }

  if (isBootstrapping) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100 p-4 dark:bg-slate-950">
        <p className="text-sm text-slate-600 dark:text-slate-300" role="status">
          Restoring session…
        </p>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 p-4 dark:bg-slate-950">
      <Card className="w-full max-w-md space-y-4 p-6">
        <div className="flex items-center gap-3">
          <img
            src="/icons.png"
            alt="Auth Service logo"
            className="brand-logo h-12 w-12 rounded-full object-cover"
          />
          <div>
            <h1 className="text-xl font-semibold">Admin Sign In</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">Secure access to Auth Service dashboard</p>
            <p className="mt-1 text-xs text-amber-800 dark:text-amber-200/90" data-testid="env-banner">
              Environment: {env.envName} — confirm the site URL matches your organization before entering credentials.
            </p>
          </div>
        </div>

        {loginSubView === "mfa" && (
          <div className="space-y-3 rounded-md border border-sky-200 bg-sky-50/80 p-4 dark:border-sky-900/50 dark:bg-sky-950/30">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Two-factor code</h2>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Enter the 6-digit code from your authenticator app (TOTP) to finish signing in.
            </p>
            <Input
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="6-digit code"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              aria-label="MFA TOTP code"
            />
            <div className="flex flex-wrap gap-2">
              <Button type="button" className="flex-1" disabled={enrollBusy} onClick={() => void onCompleteMfaLogin()}>
                {enrollBusy ? "…" : "Verify and continue"}
              </Button>
              <Button type="button" variant="outline" disabled={enrollBusy} onClick={onCancelMfa}>
                Back
              </Button>
            </div>
          </div>
        )}

        {loginSubView === "enroll" && (
          <div className="space-y-3 rounded-md border border-amber-200 bg-amber-50/80 p-4 dark:border-amber-900/50 dark:bg-amber-950/30">
            <h2 className="text-sm font-semibold text-amber-950 dark:text-amber-100">Set up two-factor authentication (TOTP)</h2>
            <p className="text-xs text-amber-900/90 dark:text-amber-200/90">
              Your organization requires 2FA. All options below use the same time-based 6-digit standard (Google Authenticator, Microsoft, Authy, etc.).
            </p>
            <label className="block text-xs font-medium text-amber-950 dark:text-amber-100" htmlFor="enroll-app">
              Authenticator app
            </label>
            <select
              id="enroll-app"
              className="w-full rounded-md border border-amber-200 bg-white px-2 py-1.5 text-sm text-slate-900 dark:border-amber-800/60 dark:bg-amber-950/40 dark:text-amber-50"
              value={authenticatorApp}
              onChange={(e) => setAuthenticatorApp(e.target.value as AuthenticatorAppId)}
            >
              {AUTHENTICATOR_APP_OPTIONS.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.label}
                </option>
              ))}
            </select>
            <p className="text-xs text-amber-900/90 dark:text-amber-200/80">{getAuthenticatorHelp(authenticatorApp)}</p>
            {otpauthUrl && (
              <p className="break-all font-mono text-xs text-slate-700 dark:text-slate-300">
                {otpauthUrl}
              </p>
            )}
            <Input
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="6-digit code"
              value={enrollCode}
              onChange={(e) => setEnrollCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              aria-label="Authenticator code"
            />
            <div className="flex flex-wrap gap-2">
              <Button type="button" className="flex-1" disabled={enrollBusy} onClick={() => void onCompleteTotpEnroll()}>
                {enrollBusy ? "…" : "Confirm and continue"}
              </Button>
              <Button type="button" variant="outline" disabled={enrollBusy} onClick={onCancelEnroll}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        <form className="space-y-3" onSubmit={form.handleSubmit(onSubmit)} noValidate>
          {rootError?.message && (
            <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200" role="alert">
              {rootError.message}
            </p>
          )}
          <Input
            id="login-tenant"
            autoComplete="off"
            placeholder="Tenant UUID"
            aria-invalid={!!form.formState.errors.tenant_id}
            aria-describedby={form.formState.errors.tenant_id ? "login-tenant-err" : undefined}
            {...form.register("tenant_id")}
            disabled={loginSubView !== "none"}
          />
          {form.formState.errors.tenant_id && (
            <p id="login-tenant-err" className="text-xs text-red-600 dark:text-red-400">
              {form.formState.errors.tenant_id.message}
            </p>
          )}

          <Input
            id="login-email"
            type="email"
            autoComplete="email"
            placeholder="Email"
            aria-invalid={!!form.formState.errors.email}
            {...form.register("email")}
            disabled={loginSubView !== "none"}
          />
          {form.formState.errors.email && (
            <p className="text-xs text-red-600 dark:text-red-400">{form.formState.errors.email.message}</p>
          )}

          <Input
            id="login-password"
            type="password"
            autoComplete="current-password"
            placeholder="Password"
            aria-invalid={!!form.formState.errors.password}
            {...form.register("password")}
            disabled={loginSubView !== "none"}
          />
          {form.formState.errors.password && (
            <p className="text-xs text-red-600 dark:text-red-400">{form.formState.errors.password.message}</p>
          )}

          <Input
            id="login-audience"
            autoComplete="off"
            placeholder="Audience"
            aria-invalid={!!form.formState.errors.audience}
            {...form.register("audience")}
            disabled={loginSubView !== "none"}
          />
          {form.formState.errors.audience && (
            <p className="text-xs text-red-600 dark:text-red-400">{form.formState.errors.audience.message}</p>
          )}

          <Button type="submit" className="w-full" disabled={isLoading || enrollBusy || loginSubView !== "none"}>
            {isLoading || enrollBusy ? "Signing in…" : "Sign In"}
          </Button>
        </form>
      </Card>
    </div>
  );
}
