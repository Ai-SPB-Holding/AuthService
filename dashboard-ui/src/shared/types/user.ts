export type User = {
  id: string;
  tenant_id: string;
  email: string;
  is_active: boolean;
  is_locked: boolean;
  email_verified: boolean;
  totp_enabled?: boolean;
  /** Set at account creation: OAuth client name, `dashboard`, `make-auth-service`, `direct`, etc. */
  registration_source?: string;
  created_at?: string;
  roles?: string[];
};

export type UserListSort = "created_at" | "email" | "registration_source";
export type UserListOrder = "asc" | "desc";
