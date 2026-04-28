-- Bind refresh tokens to the public OAuth client_id when issued via client flows (embedded login, code exchange).
-- Used to enforce client authentication on refresh for confidential clients.
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS oauth_client_public_id TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_oauth_client
    ON refresh_tokens (oauth_client_public_id)
    WHERE oauth_client_public_id IS NOT NULL;
