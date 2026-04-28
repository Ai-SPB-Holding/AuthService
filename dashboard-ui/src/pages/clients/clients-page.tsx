import { useMemo, useState } from "react";
import { useFieldArray, useForm, useWatch } from "react-hook-form";

import { env } from "@/shared/config/env";

import {
  useClientsQuery,
  useCreateClientMutation,
  useDeleteClientMutation,
  useGenerateClientIdMutation,
  useUpdateClientMutation,
} from "@/features/clients/use-clients-query";
import { getErrorMessage } from "@/shared/api/api-error";
import type { MfaPolicy } from "@/features/clients/clients-api";
import type { OAuthClientRow } from "@/shared/types/oauth-client";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Modal } from "@/shared/ui/modal";
import { DataTable } from "@/shared/ui/table";
import { EmptyState, InlineError, ListSkeleton } from "@/shared/ui/status-blocks";

type ClientForm = {
  client_id?: string;
  client_type: "public" | "confidential";
  redirect_urls: { value: string }[];
  scope_flags: {
    openid: boolean;
    profile: boolean;
    email: boolean;
    read: boolean;
    write: boolean;
  };
  allow_user_registration: boolean;
  mfa_policy: MfaPolicy;
  allow_client_totp_enrollment: boolean;
  embedded_login_enabled: boolean;
  embedded_token_audience: string;
  embedded_parent_origins: { value: string }[];
  /** v2 postMessage protocol (envelope, INIT, THEME_UPDATE); see `docs/EMBEDDED_IFRAME_PROTOCOL.md` */
  embedded_protocol_v2: boolean;
  /** Whitelisted design tokens JSON (`{ "v": 1, ... }`); leave empty to use defaults */
  embedded_ui_theme_json: string;
  user_schema: { field_name: string; field_type: string; is_auth: boolean; is_required: boolean }[];
};

const AUTH_SCOPE_OPTIONS: Array<{ key: keyof ClientForm["scope_flags"]; label: string }> = [
  { key: "openid", label: "openid (OIDC)" },
  { key: "profile", label: "profile" },
  { key: "email", label: "email" },
  { key: "read", label: "read" },
  { key: "write", label: "write" },
];

function scopesToFlags(scopes: string): ClientForm["scope_flags"] {
  const s = new Set(scopes.split(/\s+/).map((x) => x.trim()).filter(Boolean));
  return {
    openid: s.has("openid"),
    profile: s.has("profile"),
    email: s.has("email"),
    read: s.has("read"),
    write: s.has("write"),
  };
}

function flagsToScopes(flags: ClientForm["scope_flags"]): string {
  return AUTH_SCOPE_OPTIONS.filter((s) => flags[s.key]).map((s) => s.key).join(" ");
}

const defaultSchema = () => [
  { field_name: "email", field_type: "string", is_auth: true, is_required: true },
  { field_name: "password_hash", field_type: "password", is_auth: true, is_required: true },
];

const CLIENT_FORM_DEFAULTS: Required<ClientForm> = {
  client_id: "",
  client_type: "public",
  redirect_urls: [{ value: "" }],
  scope_flags: scopesToFlags("openid profile email"),
  allow_user_registration: false,
  mfa_policy: "off",
  allow_client_totp_enrollment: true,
  embedded_login_enabled: false,
  embedded_token_audience: "",
  embedded_parent_origins: [{ value: "" }],
  embedded_protocol_v2: false,
  embedded_ui_theme_json: "",
  user_schema: defaultSchema(),
};

function parseMfaPolicy(v: string | undefined): MfaPolicy {
  const s = (v ?? "off").toLowerCase();
  if (s === "optional" || s === "required" || s === "off") return s;
  return "off";
}

function normalizeUris(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  return [];
}

function formatRedirectUrisCell(v: unknown): string {
  const u = normalizeUris(v);
  return u.length ? u.join(", ") : "—";
}

function normalizeEmbeddedOriginsField(v: unknown): { value: string }[] {
  if (Array.isArray(v)) {
    const s = v.map((x) => String(x).trim()).filter(Boolean);
    return s.length ? s.map((x) => ({ value: x })) : [{ value: "" }];
  }
  return [{ value: "" }];
}

function authServiceOrigin(): string {
  try {
    return new URL(env.apiBaseUrl).origin;
  } catch {
    return env.apiBaseUrl.replace(/\/$/, "");
  }
}

/** HTML for an iframe pointing at this deployment’s `/embedded-login`. */
function embeddedIframeHtml(clientId: string): string {
  const id = clientId.trim();
  if (!id) return "";
  const base = env.apiBaseUrl.replace(/\/$/, "");
  const q = encodeURIComponent(id);
  return `<iframe
  src="${base}/embedded-login?client_id=${q}"
  title="Sign in"
  width="400"
  height="640"
  style="border:0;max-width:100%;border-radius:8px"
></iframe>`;
}

function embeddedPostMessageListenerSnippet(): string {
  const origin = authServiceOrigin();
  return `window.addEventListener("message", (event) => {
  if (event.origin !== "${origin}") return;
  const d = event.data || {};
  if (d.type === "AUTH_SUCCESS") {
    // Send tokens to your backend or store securely — never log in production
    console.log("AUTH_SUCCESS");
  }
  if (d.type === "AUTH_ERROR") {
    console.error(d.error, d.message);
  }
});`;
}

function EmbeddedEmbedPanel({ clientId }: { clientId: string }) {
  const iframe = embeddedIframeHtml(clientId);
  const listener = embeddedPostMessageListenerSnippet();
  const origin = authServiceOrigin();
  if (!clientId.trim()) {
    return (
      <p className="text-xs text-slate-500 dark:text-slate-400">
        Save a <strong>client ID</strong> to generate the embed code. If <code>/embedded-login</code> shows “Embedded iframe login is
        disabled”, enable it below and add parent origins (<code>{origin}</code> + your app).
      </p>
    );
  }
  return (
    <div className="mt-3 space-y-2 border-t border-slate-200 pt-3 dark:border-slate-700">
      <p className="text-xs font-medium text-slate-600 dark:text-slate-400">Frontend embed</p>
      <p className="text-xs text-slate-500 dark:text-slate-400">
        Requires <strong>Embedded iframe login</strong> on + <strong>Parent origins</strong> listing this API origin (
        <code className="text-xs">{origin}</code>) and every URL where the iframe is shown. The <strong>Register</strong> tab
        appears only if <strong>Allow user registration</strong> is enabled; registration completes after email code
        verification inside the iframe.
      </p>
      <label className="block text-xs text-slate-500">iframe HTML</label>
      <textarea
        readOnly
        className="min-h-[100px] w-full rounded-md border border-slate-300 bg-slate-50 px-2 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-950"
        value={iframe}
      />
      <Button
        type="button"
        variant="outline"
        className="text-xs"
        onClick={() => void navigator.clipboard.writeText(iframe)}
      >
        Copy iframe HTML
      </Button>
      <label className="mt-2 block text-xs text-slate-500">Parent page: postMessage listener</label>
      <textarea
        readOnly
        className="min-h-[160px] w-full rounded-md border border-slate-300 bg-slate-50 px-2 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-950"
        value={listener}
      />
      <Button
        type="button"
        variant="outline"
        className="text-xs"
        onClick={() => void navigator.clipboard.writeText(listener)}
      >
        Copy listener
      </Button>
    </div>
  );
}

/** Reject wildcards, fragments, and allow only https (or http on localhost) for dev. */
function assertSafeRedirectUris(uris: string[]) {
  for (const u of uris) {
    if (u.includes("*")) {
      throw new Error("Redirect URIs must not contain wildcards.");
    }
    let parsed: URL;
    try {
      parsed = new URL(u);
    } catch {
      throw new Error(`Invalid redirect URL: ${u}`);
    }
    if (parsed.hash) {
      throw new Error("Redirect URIs must not include a fragment.");
    }
    if (parsed.protocol === "https:") continue;
    if (parsed.protocol === "http:") {
      const h = parsed.hostname;
      if (h === "localhost" || h === "127.0.0.1" || h === "[::1]") continue;
    }
    throw new Error("Use https for redirect URIs, or http://localhost in development only.");
  }
}

function buildPayload(values: ClientForm): {
  client_id?: string;
  client_type: "public" | "confidential";
  redirect_uri?: string;
  redirect_urls: string[];
  scopes?: string;
  allow_user_registration: boolean;
  mfa_policy: MfaPolicy;
  allow_client_totp_enrollment: boolean;
  embedded_login_enabled: boolean;
  embedded_token_audience: string;
  embedded_parent_origins: string[];
  user_schema: { field_name: string; field_type: string; is_auth: boolean; is_required: boolean }[];
  embedded_protocol_v2: boolean;
  embedded_ui_theme?: object;
} {
  const redirect_urls = values.redirect_urls.map((x) => x.value.trim()).filter(Boolean);
  if (redirect_urls.length === 0) throw new Error("At least one redirect URL is required.");
  const schema = values.allow_user_registration ? values.user_schema : [];
  if (values.allow_user_registration) {
    const authCount = schema.filter((s) => s.is_auth).length;
    if (authCount < 1) throw new Error("At least one auth field is required.");
    const hasEmailAuth = schema.some((s) => s.field_name.trim().toLowerCase() === "email" && s.is_auth);
    if (!hasEmailAuth && authCount < 1) {
      throw new Error("If email auth is disabled, another auth field must be enabled.");
    }
  }
  const scopes = flagsToScopes(values.scope_flags).trim();
  const embedded_parent_origins = values.embedded_parent_origins.map((x) => x.value.trim()).filter(Boolean);
  if (values.embedded_login_enabled && embedded_parent_origins.length === 0) {
    throw new Error("Embedded iframe login needs at least one parent origin (e.g. https://app.example.com).");
  }
  const payload: {
    client_id?: string;
    client_type: "public" | "confidential";
    redirect_uri?: string;
    redirect_urls: string[];
    scopes?: string;
    allow_user_registration: boolean;
    mfa_policy: MfaPolicy;
    allow_client_totp_enrollment: boolean;
    embedded_login_enabled: boolean;
    embedded_token_audience: string;
    embedded_parent_origins: string[];
    user_schema: { field_name: string; field_type: string; is_auth: boolean; is_required: boolean }[];
    embedded_protocol_v2: boolean;
    embedded_ui_theme?: object;
  } = {
    client_id: values.client_id?.trim() || undefined,
    client_type: values.client_type,
    redirect_uri: redirect_urls[0],
    redirect_urls,
    allow_user_registration: values.allow_user_registration,
    mfa_policy: values.mfa_policy,
    allow_client_totp_enrollment: values.allow_client_totp_enrollment,
    embedded_login_enabled: values.embedded_login_enabled,
    embedded_token_audience: values.embedded_token_audience.trim(),
    embedded_parent_origins,
    embedded_protocol_v2: values.embedded_protocol_v2,
    user_schema: schema.map((f) => ({
      field_name: f.field_name.trim(),
      field_type: f.field_type.trim(),
      is_auth: f.is_auth,
      is_required: f.is_required,
    })),
  };
  const themeStr = values.embedded_ui_theme_json.trim();
  if (themeStr) {
    try {
      payload.embedded_ui_theme = JSON.parse(themeStr) as object;
    } catch {
      throw new Error("Embedded UI theme must be valid JSON (see docs/EMBEDDED_IFRAME_PROTOCOL.md).");
    }
  }
  if (scopes) payload.scopes = scopes;
  assertSafeRedirectUris(redirect_urls);
  return payload;
}

function clientToForm(c: OAuthClientRow): ClientForm {
  const all = normalizeUris(c.allowed_redirect_uris);
  return {
    client_id: c.client_id,
    client_type: c.client_type === "confidential" ? "confidential" : "public",
    redirect_urls: all.length ? all.map((u) => ({ value: u })) : [{ value: c.redirect_uri }],
    scope_flags: scopesToFlags(c.scopes ?? ""),
    allow_user_registration: Boolean(c.allow_user_registration),
    mfa_policy: parseMfaPolicy(c.mfa_policy as string | undefined),
    allow_client_totp_enrollment: c.allow_client_totp_enrollment !== false,
    embedded_login_enabled: Boolean(c.embedded_login_enabled),
    embedded_token_audience: (c.embedded_token_audience ?? "").trim(),
    embedded_parent_origins: normalizeEmbeddedOriginsField(c.embedded_parent_origins),
    embedded_protocol_v2: Boolean(c.embedded_protocol_v2),
    embedded_ui_theme_json: c.embedded_ui_theme != null ? JSON.stringify(c.embedded_ui_theme, null, 2) : "",
    user_schema: Array.isArray(c.user_schema)
      ? (c.user_schema as Array<{ field_name?: string; field_type?: string; is_auth?: boolean; is_required?: boolean }>).map((s) => ({
          field_name: s.field_name ?? "",
          field_type: s.field_type ?? "string",
          is_auth: Boolean(s.is_auth),
          is_required: Boolean(s.is_required),
        }))
      : defaultSchema(),
  };
}

export function ClientsPage() {
  const { data, isLoading, error, isError, refetch } = useClientsQuery();
  const createM = useCreateClientMutation();
  const generateClientIdM = useGenerateClientIdMutation();
  const updateM = useUpdateClientMutation();
  const deleteM = useDeleteClientMutation();

  const [openCreate, setOpenCreate] = useState(false);
  const [editing, setEditing] = useState<OAuthClientRow | null>(null);
  const [deleting, setDeleting] = useState<OAuthClientRow | null>(null);
  const [createdSecret, setCreatedSecret] = useState<{ clientId: string; clientSecret: string } | null>(null);

  const formCreate = useForm<ClientForm>({
    defaultValues: CLIENT_FORM_DEFAULTS,
  });
  const createRedirects = useFieldArray({ control: formCreate.control, name: "redirect_urls" });
  const createEmbeddedOrigins = useFieldArray({ control: formCreate.control, name: "embedded_parent_origins" });
  const createSchema = useFieldArray({ control: formCreate.control, name: "user_schema" });
  const allowReg = formCreate.watch("allow_user_registration");
  const schemaPreview = useMemo(() => {
    const fields = formCreate.getValues("user_schema") ?? [];
    return {
      auth_fields: fields.filter((f) => f.is_auth).map((f) => f.field_name),
      required_fields: fields.filter((f) => f.is_required).map((f) => f.field_name),
    };
  }, [formCreate.watch("user_schema")]);
  const formEdit = useForm<ClientForm>();
  const editEmbeddedOrigins = useFieldArray({ control: formEdit.control, name: "embedded_parent_origins" });
  const watchedCreateClientId = useWatch({ control: formCreate.control, name: "client_id" }) ?? "";
  const watchedEditClientId = useWatch({ control: formEdit.control, name: "client_id" }) ?? "";

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          OAuth2 clients: public metadata and masked client secret. Tenant is taken from your admin token.
        </p>
        <Button onClick={() => setOpenCreate(true)}>New client</Button>
      </div>

      {isError && error && (
        <InlineError message={getErrorMessage(error)} title="Could not load clients">
          <Button className="mt-3" variant="outline" type="button" onClick={() => void refetch()}>
            Try again
          </Button>
        </InlineError>
      )}

      {isLoading && <ListSkeleton rows={5} />}

      {!isError && !isLoading && (data?.length ?? 0) === 0 && (
        <EmptyState
          title="No OAuth clients"
          description="Create a client to use authorization code or refresh-token flows. Apply migration 0003 on the server for full redirect list and scope fields."
        />
      )}

      {!isError && !isLoading && (data?.length ?? 0) > 0 && (
        <DataTable<OAuthClientRow>
          data={data ?? []}
          columns={[
            { key: "client_id", title: "Client ID" },
            { key: "client_type", title: "Type" },
            { key: "client_secret_masked", title: "Secret" },
            { key: "redirect_uri", title: "Primary redirect" },
            {
              key: "allowed_redirect_uris",
              title: "Allowed redirect URIs",
              render: (row) => <span className="font-mono text-xs">{formatRedirectUrisCell(row.allowed_redirect_uris)}</span>,
            },
            { key: "scopes", title: "Scopes" },
            {
              key: "mfa_policy",
              title: "2FA policy",
              render: (row) => <span className="text-xs">{parseMfaPolicy(row.mfa_policy as string | undefined)}</span>,
            },
            {
              key: "embedded_login_enabled",
              title: "Iframe login",
              render: (row) => (
                <span className="text-xs">{row.embedded_login_enabled ? "On" : "—"}</span>
              ),
            },
            {
              key: "actions" as const,
              title: "Actions",
              render: (row) => (
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" type="button" onClick={() => { setEditing(row); formEdit.reset(clientToForm(row)); }}>
                    Edit
                  </Button>
                  <Button variant="danger" type="button" onClick={() => setDeleting(row)}>
                    Delete
                  </Button>
                </div>
              ),
            },
          ]}
        />
      )}

      {openCreate && (
        <Modal title="Create OAuth client" onClose={() => setOpenCreate(false)}>
          {formCreate.formState.errors.root?.message && (
            <p className="mb-3 text-sm text-red-600 dark:text-red-400" role="alert">
              {formCreate.formState.errors.root.message}
            </p>
          )}
          <form
            className="space-y-3"
            onSubmit={formCreate.handleSubmit(async (values) => {
              formCreate.clearErrors("root");
              let payload: ReturnType<typeof buildPayload>;
              try {
                payload = buildPayload(values);
              } catch (e) {
                formCreate.setError("root", { message: e instanceof Error ? e.message : "Invalid input" });
                return;
              }
              try {
                const res = await createM.mutateAsync(payload);
                setOpenCreate(false);
                formCreate.reset(CLIENT_FORM_DEFAULTS);
                if (res.client_secret) {
                  setCreatedSecret({ clientId: res.client_id, clientSecret: res.client_secret });
                }
              } catch (e) {
                formCreate.setError("root", { message: getErrorMessage(e) });
              }
            })}
            noValidate
          >
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_auto]">
              <Input placeholder="Client ID (empty = server generate)" {...formCreate.register("client_id")} />
              <Button
                type="button"
                variant="outline"
                disabled={generateClientIdM.isPending}
                onClick={async () => {
                  const v = await generateClientIdM.mutateAsync();
                  formCreate.setValue("client_id", v.client_id, { shouldDirty: true });
                }}
              >
                Generate
              </Button>
            </div>
            <label className="text-xs text-slate-500">Client Type</label>
            <select
              className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900"
              {...formCreate.register("client_type")}
            >
              <option value="public">Public (PKCE)</option>
              <option value="confidential">Confidential (Client Secret)</option>
            </select>
            <div>
              <label className="mb-2 block text-xs text-slate-500">Authorization scopes</label>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {AUTH_SCOPE_OPTIONS.map((scope) => (
                  <label key={scope.key} className="flex items-center gap-2 text-sm">
                    <input type="checkbox" {...formCreate.register(`scope_flags.${scope.key}`)} />
                    {scope.label}
                  </label>
                ))}
              </div>
            </div>
            <div>
              <label className="mb-2 block text-xs text-slate-500">Redirect URLs</label>
              <div className="space-y-2">
                {createRedirects.fields.map((f, idx) => (
                  <div key={f.id} className="flex gap-2">
                    <Input placeholder="https://app.example.com/callback" {...formCreate.register(`redirect_urls.${idx}.value`)} />
                    <Button type="button" variant="outline" onClick={() => createRedirects.remove(idx)} disabled={createRedirects.fields.length <= 1}>
                      Remove
                    </Button>
                  </div>
                ))}
                <Button type="button" variant="outline" onClick={() => createRedirects.append({ value: "" })}>
                  Add URL
                </Button>
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" {...formCreate.register("allow_user_registration")} />
              Allow user registration
            </label>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              When embedded iframe login is enabled, this also shows the <strong>Register</strong> tab on{" "}
              <code className="text-xs">/embedded-login</code> (email verification is required before sign-in).
            </p>
            <div className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
              <p className="mb-2 text-xs font-medium text-slate-600 dark:text-slate-400">Client 2FA (TOTP / Authenticator)</p>
              <label className="mb-1 block text-xs text-slate-500">Policy</label>
              <select
                className="mb-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900"
                {...formCreate.register("mfa_policy")}
              >
                <option value="off">Off</option>
                <option value="optional">Optional</option>
                <option value="required">Required</option>
              </select>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" {...formCreate.register("allow_client_totp_enrollment")} />
                Allow users to enroll Authenticator for this client
              </label>
            </div>
            <div className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
              <p className="mb-2 text-xs font-medium text-slate-600 dark:text-slate-400">Embedded iframe login</p>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" {...formCreate.register("embedded_login_enabled")} />
                Enable <code className="rounded bg-slate-100 px-1 text-xs dark:bg-slate-900">/embedded-login</code> for this client
              </label>
              <label className="mb-1 mt-2 block text-xs text-slate-500">JWT audience override (optional; default = client ID)</label>
              <Input placeholder="e.g. my-api" {...formCreate.register("embedded_token_audience")} />
              <label className="mb-1 mt-2 block text-xs text-slate-500">Parent page origins (CSP + postMessage)</label>
              <p className="mb-2 text-xs text-slate-500">Exact origins or <code className="text-xs">https://*.example.com</code></p>
              <div className="space-y-2">
                {createEmbeddedOrigins.fields.map((f, idx) => (
                  <div key={f.id} className="flex gap-2">
                    <Input placeholder="https://app.example.com" {...formCreate.register(`embedded_parent_origins.${idx}.value`)} />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => createEmbeddedOrigins.remove(idx)}
                      disabled={createEmbeddedOrigins.fields.length <= 1}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
                <Button type="button" variant="outline" onClick={() => createEmbeddedOrigins.append({ value: "" })}>
                  Add origin
                </Button>
              </div>
              <label className="mt-3 flex items-center gap-2 text-sm">
                <input type="checkbox" {...formCreate.register("embedded_protocol_v2")} />
                Embedded protocol v2 (envelope, INIT, THEME_UPDATE; see docs)
              </label>
              <label className="mb-1 mt-2 block text-xs text-slate-500">UI theme (optional JSON, whitelisted tokens)</label>
              <textarea
                className="min-h-[100px] w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
                placeholder='{"v":1,"colorScheme":"light","colors":{"primary":"#0f3d8a"}}'
                {...formCreate.register("embedded_ui_theme_json")}
              />
              <EmbeddedEmbedPanel clientId={watchedCreateClientId} />
            </div>
            {allowReg && (
              <div className="space-y-3 rounded-md border border-slate-200 p-3 dark:border-slate-800">
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" onClick={() => formCreate.setValue("user_schema", defaultSchema())}>Preset: Standard login</Button>
                  <Button type="button" variant="outline" onClick={() => formCreate.setValue("user_schema", [
                    { field_name: "username", field_type: "string", is_auth: true, is_required: true },
                    { field_name: "password_hash", field_type: "password", is_auth: true, is_required: true },
                  ])}>Preset: Username login</Button>
                  <Button type="button" variant="outline" onClick={() => formCreate.setValue("user_schema", [
                    { field_name: "phone", field_type: "string", is_auth: true, is_required: true },
                    { field_name: "password_hash", field_type: "password", is_auth: true, is_required: true },
                  ])}>Preset: Phone login</Button>
                </div>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-slate-500"><th>Field</th><th>Type</th><th>Auth</th><th>Required</th><th /></tr>
                  </thead>
                  <tbody>
                    {createSchema.fields.map((row, idx) => (
                      <tr key={row.id}>
                        <td><Input placeholder="email" {...formCreate.register(`user_schema.${idx}.field_name`)} /></td>
                        <td><Input placeholder="string" {...formCreate.register(`user_schema.${idx}.field_type`)} /></td>
                        <td className="px-2"><input type="checkbox" {...formCreate.register(`user_schema.${idx}.is_auth`)} /></td>
                        <td className="px-2"><input type="checkbox" {...formCreate.register(`user_schema.${idx}.is_required`)} /></td>
                        <td><Button type="button" variant="outline" onClick={() => createSchema.remove(idx)}>Delete</Button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <Button type="button" variant="outline" onClick={() => createSchema.append({ field_name: "", field_type: "string", is_auth: false, is_required: false })}>
                  Add field
                </Button>
                <div>
                  <p className="mb-1 text-xs text-slate-500">Preview JSON</p>
                  <pre className="rounded bg-slate-100 p-2 text-xs dark:bg-slate-950">{JSON.stringify(schemaPreview, null, 2)}</pre>
                </div>
              </div>
            )}
            <Button type="submit" className="w-full" disabled={createM.isPending}>
              {createM.isPending ? "Creating…" : "Create"}
            </Button>
          </form>
        </Modal>
      )}

      {createdSecret && (
        <Modal title="Client created (save secret now)" onClose={() => setCreatedSecret(null)}>
          <p className="mb-2 text-sm text-slate-600 dark:text-slate-400">Client ID: <span className="font-mono">{createdSecret.clientId}</span></p>
          <p className="mb-2 text-sm text-red-600 dark:text-red-400">This secret is shown only once.</p>
          <textarea className="min-h-[88px] w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-900" readOnly value={createdSecret.clientSecret} />
          <EmbeddedEmbedPanel clientId={createdSecret.clientId} />
          <div className="mt-3 flex gap-2">
            <Button type="button" variant="outline" onClick={async () => navigator.clipboard.writeText(createdSecret.clientSecret)}>Copy secret</Button>
            <Button type="button" onClick={() => setCreatedSecret(null)}>Done</Button>
          </div>
        </Modal>
      )}

      {editing && (
        <Modal title="Edit OAuth client" onClose={() => setEditing(null)}>
          {formEdit.formState.errors.root?.message && (
            <p className="mb-3 text-sm text-red-600 dark:text-red-400" role="alert">
              {formEdit.formState.errors.root.message}
            </p>
          )}
          <p className="mb-2 text-sm text-slate-600 dark:text-slate-400">Secret: {editing.client_secret_masked}</p>
          <form
            className="space-y-3"
            onSubmit={formEdit.handleSubmit(async (values) => {
              formEdit.clearErrors("root");
              let payload: ReturnType<typeof buildPayload>;
              try {
                payload = buildPayload(values);
              } catch (e) {
                formEdit.setError("root", { message: e instanceof Error ? e.message : "Invalid input" });
                return;
              }
              try {
                await updateM.mutateAsync({ id: editing.id, payload });
                setEditing(null);
              } catch (e) {
                formEdit.setError("root", { message: getErrorMessage(e) });
              }
            })}
            noValidate
          >
            <Input placeholder="Client ID" {...formEdit.register("client_id", { required: true })} />
            <Input placeholder="Primary redirect URI" {...formEdit.register("redirect_urls.0.value", { required: true })} />
            <div>
              <label className="mb-2 block text-xs text-slate-500">Authorization scopes</label>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {AUTH_SCOPE_OPTIONS.map((scope) => (
                  <label key={scope.key} className="flex items-center gap-2 text-sm">
                    <input type="checkbox" {...formEdit.register(`scope_flags.${scope.key}`)} />
                    {scope.label}
                  </label>
                ))}
              </div>
            </div>
            <div>
              <label className="mb-1 block text-xs text-slate-500">Additional allowed redirect URIs (one per line)</label>
              <textarea
                className="min-h-[88px] w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-slate-500 focus:ring-2 dark:border-slate-700 dark:bg-slate-900"
                rows={4}
                value=""
                readOnly
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" {...formEdit.register("allow_user_registration")} />
              Allow user registration
            </label>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Enables the <strong>Register</strong> tab on <code className="text-xs">/embedded-login</code> when embedded login is on
              (email verification required).
            </p>
            <div className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
              <p className="mb-2 text-xs font-medium text-slate-600 dark:text-slate-400">Client 2FA (TOTP / Authenticator)</p>
              <label className="mb-1 block text-xs text-slate-500">Policy</label>
              <select
                className="mb-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900"
                {...formEdit.register("mfa_policy")}
              >
                <option value="off">Off</option>
                <option value="optional">Optional</option>
                <option value="required">Required</option>
              </select>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" {...formEdit.register("allow_client_totp_enrollment")} />
                Allow users to enroll Authenticator for this client
              </label>
            </div>
            <div className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
              <p className="mb-2 text-xs font-medium text-slate-600 dark:text-slate-400">Embedded iframe login</p>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" {...formEdit.register("embedded_login_enabled")} />
                Enable <code className="rounded bg-slate-100 px-1 text-xs dark:bg-slate-900">/embedded-login</code>
              </label>
              <label className="mb-1 mt-2 block text-xs text-slate-500">JWT audience override (optional)</label>
              <Input placeholder="Default: client ID" {...formEdit.register("embedded_token_audience")} />
              <label className="mb-1 mt-2 block text-xs text-slate-500">Parent origins</label>
              <div className="space-y-2">
                {editEmbeddedOrigins.fields.map((f, idx) => (
                  <div key={f.id} className="flex gap-2">
                    <Input placeholder="https://app.example.com" {...formEdit.register(`embedded_parent_origins.${idx}.value`)} />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => editEmbeddedOrigins.remove(idx)}
                      disabled={editEmbeddedOrigins.fields.length <= 1}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
                <Button type="button" variant="outline" onClick={() => editEmbeddedOrigins.append({ value: "" })}>
                  Add origin
                </Button>
              </div>
              <label className="mt-3 flex items-center gap-2 text-sm">
                <input type="checkbox" {...formEdit.register("embedded_protocol_v2")} />
                Embedded protocol v2 (envelope, INIT, THEME_UPDATE)
              </label>
              <label className="mb-1 mt-2 block text-xs text-slate-500">UI theme (optional JSON)</label>
              <textarea
                className="min-h-[100px] w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
                placeholder='{"v":1,"colorScheme":"light"}'
                {...formEdit.register("embedded_ui_theme_json")}
              />
              <EmbeddedEmbedPanel clientId={watchedEditClientId} />
            </div>
            <Button type="submit" className="w-full" disabled={updateM.isPending}>
              {updateM.isPending ? "Saving…" : "Save"}
            </Button>
          </form>
        </Modal>
      )}

      {deleting && (
        <Modal title="Delete client?" onClose={() => setDeleting(null)}>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            Delete <span className="font-medium">{deleting.client_id}</span>? Applications using it will fail until reconfigured.
          </p>
          {deleteM.isError && <p className="mt-2 text-sm text-red-600">{getErrorMessage(deleteM.error)}</p>}
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="outline" type="button" onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              type="button"
              disabled={deleteM.isPending}
              onClick={async () => {
                try {
                  await deleteM.mutateAsync(deleting.id);
                  setDeleting(null);
                } catch {
                  // error shown above
                }
              }}
            >
              {deleteM.isPending ? "Deleting…" : "Delete"}
            </Button>
          </div>
        </Modal>
      )}
    </div>
  );
}
