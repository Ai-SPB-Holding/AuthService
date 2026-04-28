-- TOTP 2FA + email confirmation codes
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret_enc BYTEA,
    ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS totp_enabled_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS email_verifications (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    purpose TEXT NOT NULL DEFAULT 'register',
    tenant_id UUID NOT NULL
);

CREATE INDEX IF NOT EXISTS email_verifications_user_purpose
    ON email_verifications (user_id, purpose);

CREATE INDEX IF NOT EXISTS email_verifications_expires
    ON email_verifications (expires_at);

CREATE INDEX IF NOT EXISTS email_verifications_tenant
    ON email_verifications (tenant_id);
