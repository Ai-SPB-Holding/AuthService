-- Authorization codes: one-time, nonce, scope
ALTER TABLE auth_codes
    ADD COLUMN IF NOT EXISTS nonce TEXT;
ALTER TABLE auth_codes
    ADD COLUMN IF NOT EXISTS scope TEXT;
ALTER TABLE auth_codes
    ADD COLUMN IF NOT EXISTS consumed BOOLEAN NOT NULL DEFAULT FALSE;

-- OAuth clients: public vs confidential, hashed secret
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS client_type TEXT NOT NULL DEFAULT 'public';
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS client_secret_argon2 TEXT;
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS allow_user_registration BOOLEAN NOT NULL DEFAULT FALSE;

-- Globally unique client_id for /authorize lookup (fail migration if duplicates exist)
-- Run: SELECT client_id, COUNT(*) FROM clients GROUP BY client_id HAVING COUNT(*) > 1;
CREATE UNIQUE INDEX IF NOT EXISTS uq_clients_client_id ON clients (client_id);

CREATE TABLE IF NOT EXISTS client_user_schema (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    field_name TEXT NOT NULL,
    field_type TEXT NOT NULL,
    is_auth BOOLEAN NOT NULL DEFAULT FALSE,
    is_required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(client_id, field_name)
);

-- Refresh token rotation / reuse detection
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS token_family_id UUID;
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS rotated_from_id UUID;
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS jti_in_token TEXT;

UPDATE refresh_tokens SET token_family_id = id WHERE token_family_id IS NULL;

-- Optional: pre-fill from legacy plaintext secret for verification path in app (prefer rotate-secret in admin)
-- App verifies Argon2 OR legacy plaintext until migrated.
