import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import { Link } from "react-router-dom";

import { useAuthStore } from "@/features/auth/auth-store";
import {
  adminUserClient2faDisable,
  adminUserClient2faSetup,
  adminUserClient2faVerify,
  getAdminUserClient2faStatus,
  listClients,
} from "@/features/clients/clients-api";
import { clientsQueryKey } from "@/features/clients/use-clients-query";
import {
  useCreateUserMutation,
  useDeleteUserMutation,
  useGenerateTenantIdMutation,
  usePatchUserMutation,
  useResetEmailVerificationMutation,
  useSendVerificationEmailMutation,
  useUsersQuery,
  useVerifyEmailAdminMutation,
} from "@/features/users/use-users-query";
import { getUser } from "@/features/users/users-api";
import { getErrorMessage } from "@/shared/api/api-error";
import { parseAccessTokenPayload } from "@/shared/lib/jwt";
import { useDebouncedValue } from "@/shared/hooks/use-debounced-value";
import type { User, UserListOrder, UserListSort } from "@/shared/types/user";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { EmptyState, InlineError, ListSkeleton } from "@/shared/ui/status-blocks";
import { Modal } from "@/shared/ui/modal";
import { UsersTable } from "@/widgets/users-table/users-table";

type NewUserForm = {
  tenant_id: string;
  email: string;
  password: string;
  /** Stored as `registration_source` (default dashboard). */
  registration_source: string;
};

const SEARCH_DEBOUNCE_MS = 300;

const uuidRe =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(s: string) {
  return uuidRe.test(s.trim());
}

export function UsersPage() {
  const accessToken = useAuthStore((s) => s.accessToken);
  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<User | null>(null);
  const [editEmail, setEditEmail] = useState("");
  const [editTenantId, setEditTenantId] = useState("");
  const [editError, setEditError] = useState<string | null>(null);
  /** OAuth client row UUID for per-client 2FA admin tools. */
  const [mfaClientRowId, setMfaClientRowId] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaSetup, setMfaSetup] = useState<{ otpauth_url: string; secret_base32: string } | null>(null);
  const [mfaActionBusy, setMfaActionBusy] = useState(false);

  const debounced = useDebouncedValue(search, SEARCH_DEBOUNCE_MS);
  const [listSort, setListSort] = useState<UserListSort>("created_at");
  const [listOrder, setListOrder] = useState<UserListOrder>("desc");
  const { data, isLoading, isFetching, error, isError, refetch } = useUsersQuery(debounced, listSort, listOrder);
  const createUser = useCreateUserMutation();
  const patchUser = usePatchUserMutation();
  const deleteUser = useDeleteUserMutation();
  const sendVerification = useSendVerificationEmailMutation();
  const verifyEmailAdmin = useVerifyEmailAdminMutation();
  const resetEmailVerification = useResetEmailVerificationMutation();
  const generateTenantId = useGenerateTenantIdMutation();

  const clientsFor2fa = useQuery({
    queryKey: clientsQueryKey,
    queryFn: listClients,
    enabled: Boolean(editUser),
    staleTime: 15_000,
  });

  /** OAuth clients for the edited user’s tenant (deployment-wide admins get all clients from the API; list must be scoped). */
  const clientsForUser2fa = useMemo(() => {
    if (!editUser) return [];
    return (clientsFor2fa.data ?? []).filter((c) => c.tenant_id === editUser.tenant_id);
  }, [clientsFor2fa.data, editUser]);

  useEffect(() => {
    if (!mfaClientRowId) return;
    if (!clientsForUser2fa.some((c) => c.id === mfaClientRowId)) {
      setMfaClientRowId("");
      setMfaSetup(null);
      setMfaCode("");
    }
  }, [clientsForUser2fa, mfaClientRowId]);

  const userClient2faStatus = useQuery({
    queryKey: [...clientsQueryKey, "user-2fa", editUser?.id, mfaClientRowId] as const,
    queryFn: () => {
      if (!editUser || !mfaClientRowId) {
        return Promise.resolve({ client_totp_enabled: false });
      }
      return getAdminUserClient2faStatus(mfaClientRowId, editUser.id);
    },
    enabled: Boolean(editUser) && mfaClientRowId.length > 0,
  });

  const form = useForm<NewUserForm>({
    defaultValues: {
      tenant_id: "",
      email: "",
      password: "",
      registration_source: "dashboard",
    },
  });

  useEffect(() => {
    if (!createOpen) return;
    const tid = accessToken ? parseAccessTokenPayload(accessToken)?.tenant_id : undefined;
    form.reset({
      tenant_id: typeof tid === "string" && tid ? tid : "",
      email: "",
      password: "",
      registration_source: "dashboard",
    });
  }, [createOpen, accessToken, form]);

  useEffect(() => {
    if (!editUser) {
      setEditError(null);
      return;
    }
    setEditEmail(editUser.email);
    setEditTenantId(editUser.tenant_id);
    setEditError(null);
    setMfaClientRowId("");
    setMfaCode("");
    setMfaSetup(null);
  }, [editUser]);

  function handleColumnSort(key: UserListSort) {
    if (key === listSort) {
      setListOrder((o) => (o === "asc" ? "desc" : "asc"));
    } else {
      setListSort(key);
      setListOrder(key === "created_at" ? "desc" : "asc");
    }
  }

  async function handleCreate(values: NewUserForm) {
    form.clearErrors("root");
    if (!isUuid(values.tenant_id)) {
      form.setError("root", { message: "Tenant ID must be a valid UUID." });
      return;
    }
    try {
      await createUser.mutateAsync(values);
      setCreateOpen(false);
      const tid = accessToken ? parseAccessTokenPayload(accessToken)?.tenant_id : undefined;
      form.reset({
        tenant_id: typeof tid === "string" && tid ? tid : "",
        email: "",
        password: "",
        registration_source: "dashboard",
      });
    } catch (e) {
      form.setError("root", { message: getErrorMessage(e) });
    }
  }

  async function refreshEditUser(id: string) {
    const u = await getUser(id);
    setEditUser(u);
  }

  async function handleSaveProfile() {
    if (!editUser) return;
    setEditError(null);
    if (!isUuid(editTenantId)) {
      setEditError("Tenant ID must be a valid UUID.");
      return;
    }
    const body: { email?: string; tenant_id?: string } = {};
    if (editEmail.trim() !== editUser.email) body.email = editEmail.trim();
    if (editTenantId.trim() !== editUser.tenant_id) body.tenant_id = editTenantId.trim();
    if (Object.keys(body).length === 0) {
      setEditError("No changes to save.");
      return;
    }
    try {
      const u = await patchUser.mutateAsync({ id: editUser.id, body });
      setEditUser(u);
    } catch (e) {
      setEditError(getErrorMessage(e));
    }
  }

  async function handleToggleLock() {
    if (!editUser) return;
    setEditError(null);
    try {
      const u = await patchUser.mutateAsync({
        id: editUser.id,
        body: { is_locked: !editUser.is_locked },
      });
      setEditUser(u);
    } catch (e) {
      setEditError(getErrorMessage(e));
    }
  }

  async function handleDeleteUser() {
    if (!editUser) return;
    if (!window.confirm(`Delete user ${editUser.email}? This cannot be undone.`)) return;
    setEditError(null);
    try {
      await deleteUser.mutateAsync(editUser.id);
      setEditUser(null);
    } catch (e) {
      setEditError(getErrorMessage(e));
    }
  }

  async function handleGenerateTenantForCreate() {
    form.clearErrors("root");
    try {
      const id = await generateTenantId.mutateAsync();
      form.setValue("tenant_id", id, { shouldValidate: true, shouldDirty: true });
    } catch (e) {
      form.setError("root", { message: getErrorMessage(e) });
    }
  }

  async function handleGenerateTenantForEdit() {
    if (!editUser) return;
    setEditError(null);
    try {
      const id = await generateTenantId.mutateAsync();
      setEditTenantId(id);
    } catch (e) {
      setEditError(getErrorMessage(e));
    }
  }

  const showListSkeleton = isLoading;
  const listEmpty = !isError && !isLoading && (data?.length ?? 0) === 0;
  const listError = isError && error;

  const editBusy =
    patchUser.isPending ||
    deleteUser.isPending ||
    sendVerification.isPending ||
    verifyEmailAdmin.isPending ||
    resetEmailVerification.isPending;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="max-w-sm flex-1">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search users by email"
            type="search"
            aria-label="Search users by email"
            autoComplete="off"
          />
          {isFetching && !isLoading && <p className="mt-1 text-xs text-slate-500">Updating…</p>}
        </div>
        <Button onClick={() => setCreateOpen(true)}>New User</Button>
      </div>

      {listError && (
        <InlineError message={getErrorMessage(listError)} title="Could not load users">
          <Button className="mt-3" variant="outline" type="button" onClick={() => void refetch()}>
            Try again
          </Button>
        </InlineError>
      )}

      {showListSkeleton && <ListSkeleton rows={5} />}

      {!isError && !showListSkeleton && listEmpty && (
        <EmptyState
          title="No users to display"
          description={
            debounced
              ? "No users match this search."
              : "No users in this tenant yet, or add one with New User."
          }
        />
      )}

      {!isError && !showListSkeleton && !listEmpty && (
        <UsersTable
          users={data ?? []}
          onEdit={(u) => setEditUser(u)}
          sort={listSort}
          order={listOrder}
          onColumnSort={handleColumnSort}
        />
      )}

      {createOpen && (
        <Modal title="Create user" onClose={() => setCreateOpen(false)}>
          {form.formState.errors.root?.message && (
            <p className="mb-3 text-sm text-red-600 dark:text-red-400" role="alert">
              {form.formState.errors.root.message}
            </p>
          )}
          <form className="space-y-3" onSubmit={form.handleSubmit(handleCreate)} noValidate>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Tenant ID</label>
              <div className="flex gap-2">
                <Input
                  className="min-w-0 flex-1"
                  placeholder="UUID"
                  autoComplete="off"
                  {...form.register("tenant_id", { required: true })}
                />
                <Button
                  type="button"
                  variant="outline"
                  className="shrink-0"
                  disabled={generateTenantId.isPending}
                  onClick={() => void handleGenerateTenantForCreate()}
                >
                  {generateTenantId.isPending ? "…" : "Generate"}
                </Button>
              </div>
            </div>
            <Input type="email" placeholder="Email" autoComplete="off" {...form.register("email", { required: true })} />
            <Input
              type="password"
              placeholder="Password (min. 8 characters)"
              autoComplete="new-password"
              {...form.register("password", { required: true, minLength: 8 })}
            />
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Registration source</label>
              <Input
                placeholder="e.g. dashboard, make-auth-service"
                autoComplete="off"
                {...form.register("registration_source")}
              />
              <p className="mt-1 text-xs text-slate-500">Stored in the database as the client / origin of this account (default: dashboard).</p>
            </div>
            <Button type="submit" className="w-full" disabled={createUser.isPending}>
              {createUser.isPending ? "Creating…" : "Create"}
            </Button>
          </form>
        </Modal>
      )}

      {editUser && (
        <Modal title={`Edit user`} onClose={() => setEditUser(null)} className="max-w-xl">
          <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">{editUser.email}</p>

          {editError && (
            <p className="mb-3 text-sm text-red-600 dark:text-red-400" role="alert">
              {editError}
            </p>
          )}

          <div className="space-y-4">
            <div className="space-y-2">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400">Email</label>
              <Input value={editEmail} onChange={(e) => setEditEmail(e.target.value)} type="email" autoComplete="off" />
            </div>
            <div className="space-y-2">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400">Tenant ID</label>
              <div className="flex gap-2">
                <Input
                  className="min-w-0 flex-1 font-mono text-xs"
                  value={editTenantId}
                  onChange={(e) => setEditTenantId(e.target.value)}
                  autoComplete="off"
                />
                <Button
                  type="button"
                  variant="outline"
                  className="shrink-0"
                  disabled={generateTenantId.isPending}
                  onClick={() => void handleGenerateTenantForEdit()}
                >
                  {generateTenantId.isPending ? "…" : "Generate"}
                </Button>
              </div>
              <p className="text-xs text-slate-500">
                Changing tenant moves the user in the database (roles for the old tenant are removed).
              </p>
            </div>
            <Button type="button" className="w-full" variant="outline" disabled={editBusy} onClick={() => void handleSaveProfile()}>
              Save email & tenant
            </Button>

            <div className="flex flex-wrap gap-2 border-t border-slate-200 pt-4 dark:border-slate-700">
              {!editUser.email_verified && (
                <>
                  <Button
                    type="button"
                    variant="outline"
                    className="px-3 py-1.5 text-xs"
                    disabled={editBusy}
                    onClick={() => {
                      void (async () => {
                        setEditError(null);
                        try {
                          await sendVerification.mutateAsync(editUser.id);
                          await refreshEditUser(editUser.id);
                        } catch (e) {
                          setEditError(getErrorMessage(e));
                        }
                      })();
                    }}
                  >
                    Send verification email
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    className="px-3 py-1.5 text-xs"
                    disabled={editBusy}
                    onClick={() => {
                      void (async () => {
                        setEditError(null);
                        try {
                          await verifyEmailAdmin.mutateAsync(editUser.id);
                          await refreshEditUser(editUser.id);
                        } catch (e) {
                          setEditError(getErrorMessage(e));
                        }
                      })();
                    }}
                  >
                    Confirm email (admin)
                  </Button>
                </>
              )}
              {editUser.email_verified && (
                <Button
                  type="button"
                  variant="outline"
                  className="px-3 py-1.5 text-xs"
                  disabled={editBusy}
                  onClick={() => {
                    void (async () => {
                      setEditError(null);
                      try {
                        await resetEmailVerification.mutateAsync(editUser.id);
                        await refreshEditUser(editUser.id);
                      } catch (e) {
                        setEditError(getErrorMessage(e));
                      }
                    })();
                  }}
                >
                  Reset email verification
                </Button>
              )}
              <Button
                type="button"
                variant="outline"
                className="px-3 py-1.5 text-xs"
                disabled={editBusy}
                onClick={() => void handleToggleLock()}
              >
                {editUser.is_locked ? "Unlock account" : "Block account"}
              </Button>
              <Button
                type="button"
                variant="danger"
                className="px-3 py-1.5 text-xs"
                disabled={editBusy}
                onClick={() => void handleDeleteUser()}
              >
                Delete user
              </Button>
            </div>

            <dl className="grid grid-cols-1 gap-2 text-xs text-slate-600 dark:text-slate-400 sm:grid-cols-2">
              <div>
                <dt className="font-medium text-slate-500 dark:text-slate-500">Source (client / origin)</dt>
                <dd className="font-mono">{editUser.registration_source ?? "—"}</dd>
              </div>
              <div>
                <dt className="font-medium text-slate-500 dark:text-slate-500">Registered (DB)</dt>
                <dd>
                  {editUser.created_at
                    ? new Date(editUser.created_at).toLocaleString(undefined, {
                        dateStyle: "medium",
                        timeStyle: "short",
                      })
                    : "—"}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-slate-500 dark:text-slate-500">Active</dt>
                <dd>{editUser.is_active ? "Yes" : "No"}</dd>
              </div>
              <div>
                <dt className="font-medium text-slate-500 dark:text-slate-500">TOTP (global)</dt>
                <dd>{editUser.totp_enabled ? "On" : "Off"}</dd>
              </div>
            </dl>

            <div className="space-y-3 border-t border-slate-200 pt-4 dark:border-slate-700">
              <p className="text-xs font-medium text-slate-600 dark:text-slate-400">2FA for OAuth client (per client)</p>
              <p className="text-xs text-slate-500 dark:text-slate-500">
                Separate from global TOTP: you need an{" "}
                <Link to="/clients" className="text-slate-700 underline dark:text-slate-300">
                  OAuth client
                </Link>{" "}
                row for this organization before you can enroll a per-client authenticator.
              </p>
              {clientsFor2fa.isError && (
                <p className="text-xs text-amber-600">Could not load clients list. Open Clients page and retry.</p>
              )}
              {clientsFor2fa.isSuccess && clientsForUser2fa.length === 0 && !clientsFor2fa.isError && (
                <p className="rounded-md border border-amber-200 bg-amber-50 px-2 py-1.5 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-100">
                  No OAuth clients exist for this user&apos;s tenant yet (e.g. after{" "}
                  <span className="font-mono">make user-add</span> only a user is created, not a client).{" "}
                  <Link to="/clients" className="font-medium underline">
                    Add a client
                  </Link>{" "}
                  for this tenant, then select it here.
                </p>
              )}
              <div className="space-y-1">
                <label className="text-xs text-slate-500">OAuth client</label>
                <select
                  className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900"
                  value={mfaClientRowId}
                  onChange={(e) => {
                    setMfaClientRowId(e.target.value);
                    setMfaSetup(null);
                    setMfaCode("");
                  }}
                  disabled={clientsForUser2fa.length === 0}
                >
                  <option value="">— select —</option>
                  {clientsForUser2fa.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.client_id} ({c.mfa_policy ?? "off"})
                    </option>
                  ))}
                </select>
              </div>
              {mfaClientRowId && (
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Status:{" "}
                  {userClient2faStatus.isLoading
                    ? "…"
                    : userClient2faStatus.data?.client_totp_enabled
                      ? "On"
                      : "Off"}
                </p>
              )}
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="text-xs"
                  disabled={!mfaClientRowId || mfaActionBusy}
                  onClick={() => {
                    if (!editUser || !mfaClientRowId) return;
                    void (async () => {
                      setEditError(null);
                      setMfaActionBusy(true);
                      try {
                        const s = await adminUserClient2faSetup(mfaClientRowId, editUser.id);
                        setMfaSetup(s);
                        await userClient2faStatus.refetch();
                      } catch (e) {
                        setEditError(getErrorMessage(e));
                      } finally {
                        setMfaActionBusy(false);
                      }
                    })();
                  }}
                >
                  {mfaActionBusy ? "…" : "Setup (QR / secret)"}
                </Button>
              </div>
              {mfaSetup && (
                <div className="space-y-2 rounded bg-slate-100 p-2 text-xs dark:bg-slate-900">
                  <p className="font-mono break-all">{mfaSetup.otpauth_url}</p>
                  <p>
                    <span className="text-slate-500">secret: </span>
                    {mfaSetup.secret_base32}
                  </p>
                </div>
              )}
              <div className="space-y-1">
                <label className="text-xs text-slate-500">6-digit code</label>
                <Input
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 8))}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="000000"
                />
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="text-xs"
                  disabled={!mfaClientRowId || mfaCode.length < 6 || mfaActionBusy}
                  onClick={() => {
                    if (!editUser || !mfaClientRowId) return;
                    void (async () => {
                      setEditError(null);
                      setMfaActionBusy(true);
                      try {
                        await adminUserClient2faVerify(mfaClientRowId, editUser.id, mfaCode);
                        setMfaCode("");
                        setMfaSetup(null);
                        await userClient2faStatus.refetch();
                      } catch (e) {
                        setEditError(getErrorMessage(e));
                      } finally {
                        setMfaActionBusy(false);
                      }
                    })();
                  }}
                >
                  Verify &amp; enable
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="text-xs"
                  disabled={!mfaClientRowId || mfaCode.length < 6 || mfaActionBusy}
                  onClick={() => {
                    if (!editUser || !mfaClientRowId) return;
                    void (async () => {
                      setEditError(null);
                      setMfaActionBusy(true);
                      try {
                        await adminUserClient2faDisable(mfaClientRowId, editUser.id, mfaCode);
                        setMfaCode("");
                        setMfaSetup(null);
                        await userClient2faStatus.refetch();
                      } catch (e) {
                        setEditError(getErrorMessage(e));
                      } finally {
                        setMfaActionBusy(false);
                      }
                    })();
                  }}
                >
                  Disable with code
                </Button>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
