-- Deferred embedded registration when client MFA policy is `required` (user row after email + client TOTP).

CREATE TABLE IF NOT EXISTS embedded_pending_registrations (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    oauth_client_id TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    registration_source TEXT NOT NULL,
    email_verified_at TIMESTAMPTZ,
    client_totp_secret_enc BYTEA,
    client_totp_verified_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_embedded_pending_tenant_email
    ON embedded_pending_registrations (tenant_id, LOWER(email));

CREATE INDEX IF NOT EXISTS idx_embedded_pending_expires
    ON embedded_pending_registrations (expires_at);

ALTER TABLE email_verifications
    ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE email_verifications
    ADD COLUMN IF NOT EXISTS pending_registration_id UUID
    REFERENCES embedded_pending_registrations(id) ON DELETE CASCADE;

ALTER TABLE email_verifications DROP CONSTRAINT IF EXISTS email_verifications_target;

ALTER TABLE email_verifications ADD CONSTRAINT email_verifications_target CHECK (
    (user_id IS NOT NULL AND pending_registration_id IS NULL)
    OR (user_id IS NULL AND pending_registration_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_email_verif_pending_purpose
    ON email_verifications (pending_registration_id, purpose)
    WHERE pending_registration_id IS NOT NULL;
