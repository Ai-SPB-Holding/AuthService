-- Where the user account was created (e.g. OAuth client_id, `dashboard`, `make-auth-service`, `direct`).
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS registration_source TEXT NOT NULL DEFAULT 'unknown';

COMMENT ON COLUMN users.registration_source IS 'Origin label at signup (client name, tool name, or direct).';
