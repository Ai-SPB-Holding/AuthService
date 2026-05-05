-- Embedded iframe login: per-client CSP frame-ancestors, JWT aud override, opt-in flag
CREATE SCHEMA IF NOT EXISTS auth;

ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS embedded_login_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS embedded_token_audience TEXT;
ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS embedded_parent_origins JSONB NOT NULL DEFAULT '[]'::jsonb;
