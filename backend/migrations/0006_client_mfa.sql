-- Per-OAuth-client MFA (Google Authenticator / TOTP), separate from users.totp_*

ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS mfa_policy TEXT NOT NULL DEFAULT 'off'
        CHECK (mfa_policy IN ('off', 'optional', 'required'));
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS allow_client_totp_enrollment BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS client_user_mfa (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    oauth_client_row_id UUID NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    totp_secret_enc BYTEA,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    totp_enabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_client_user_mfa UNIQUE (oauth_client_row_id, user_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_client_user_mfa_user ON client_user_mfa (user_id, tenant_id);
