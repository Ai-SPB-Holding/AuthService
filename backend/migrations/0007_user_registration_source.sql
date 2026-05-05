-- Where the user account was created (e.g. OAuth client_id, `dashboard`, `make-auth-service`, `direct`).
CREATE SCHEMA IF NOT EXISTS auth;

ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS registration_source TEXT NOT NULL DEFAULT 'unknown';

COMMENT ON COLUMN auth.users.registration_source IS 'Origin label at signup (client name, tool name, or direct).';
