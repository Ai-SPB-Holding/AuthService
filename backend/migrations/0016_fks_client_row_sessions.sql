-- FKs and internal client_row_id on auth artifacts; refresh token session metadata; optional OAuth client row on refresh.
CREATE SCHEMA IF NOT EXISTS auth;

-- auth_codes: bind to clients.id
ALTER TABLE auth.auth_codes ADD COLUMN IF NOT EXISTS client_row_id UUID;
UPDATE auth.auth_codes ac
SET client_row_id = c.id
FROM auth.clients c
WHERE c.tenant_id = ac.tenant_id
  AND c.client_id = ac.client_id
  AND ac.client_row_id IS NULL;
DELETE FROM auth.auth_codes WHERE client_row_id IS NULL;
ALTER TABLE auth.auth_codes ALTER COLUMN client_row_id SET NOT NULL;
ALTER TABLE auth.auth_codes
    ADD CONSTRAINT auth_codes_client_row_id_fkey FOREIGN KEY (client_row_id) REFERENCES auth.clients (id) ON DELETE CASCADE;

ALTER TABLE auth.auth_codes ADD CONSTRAINT auth_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE;

-- refresh_tokens: OAuth client row + user FK; session columns
ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS oauth_client_row_id UUID;
UPDATE auth.refresh_tokens rt
SET oauth_client_row_id = c.id
FROM auth.clients c
WHERE rt.oauth_client_public_id IS NOT NULL
  AND c.tenant_id = rt.tenant_id
  AND c.client_id = rt.oauth_client_public_id
  AND rt.oauth_client_row_id IS NULL;

DELETE FROM auth.refresh_tokens r WHERE NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = r.user_id);
ALTER TABLE auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE;

ALTER TABLE auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_oauth_client_row_id_fkey FOREIGN KEY (oauth_client_row_id) REFERENCES auth.clients (id) ON DELETE SET NULL;

ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS session_status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE auth.refresh_tokens DROP CONSTRAINT IF EXISTS refresh_tokens_session_status_check;
ALTER TABLE auth.refresh_tokens ADD CONSTRAINT refresh_tokens_session_status_check
    CHECK (session_status IN ('active', 'revoked', 'expired'));

UPDATE auth.refresh_tokens SET session_status = CASE WHEN revoked THEN 'revoked' ELSE 'active' END;

-- Broken rotation pointers would block FK
UPDATE auth.refresh_tokens rt
SET rotated_from_id = NULL
WHERE rt.rotated_from_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM auth.refresh_tokens r2 WHERE r2.id = rt.rotated_from_id);

ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS revocation_reason TEXT;
ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS login_ip INET;
ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS user_agent_hash TEXT;

ALTER TABLE auth.refresh_tokens DROP CONSTRAINT IF EXISTS refresh_tokens_rotated_from_id_fkey;
ALTER TABLE auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_rotated_from_id_fkey FOREIGN KEY (rotated_from_id) REFERENCES auth.refresh_tokens (id) ON DELETE SET NULL;

-- embedded_exchange_codes
ALTER TABLE auth.embedded_exchange_codes ADD COLUMN IF NOT EXISTS client_row_id UUID;
UPDATE auth.embedded_exchange_codes e
SET client_row_id = c.id
FROM auth.clients c
WHERE c.tenant_id = e.tenant_id
  AND c.client_id = e.oauth_client_public_id
  AND e.client_row_id IS NULL;
DELETE FROM auth.embedded_exchange_codes WHERE client_row_id IS NULL;
ALTER TABLE auth.embedded_exchange_codes ALTER COLUMN client_row_id SET NOT NULL;
ALTER TABLE auth.embedded_exchange_codes
    ADD CONSTRAINT embedded_exchange_codes_client_row_id_fkey FOREIGN KEY (client_row_id) REFERENCES auth.clients (id) ON DELETE CASCADE;
ALTER TABLE auth.embedded_exchange_codes
    ADD CONSTRAINT embedded_exchange_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE;

-- embedded_pending_registrations
ALTER TABLE auth.embedded_pending_registrations ADD COLUMN IF NOT EXISTS oauth_client_row_id UUID;
UPDATE auth.embedded_pending_registrations p
SET oauth_client_row_id = c.id
FROM auth.clients c
WHERE c.tenant_id = p.tenant_id
  AND c.client_id = p.oauth_client_id
  AND p.oauth_client_row_id IS NULL;
DELETE FROM auth.embedded_pending_registrations WHERE oauth_client_row_id IS NULL;
ALTER TABLE auth.embedded_pending_registrations ALTER COLUMN oauth_client_row_id SET NOT NULL;
ALTER TABLE auth.embedded_pending_registrations
    ADD CONSTRAINT embedded_pending_oauth_client_row_id_fkey FOREIGN KEY (oauth_client_row_id) REFERENCES auth.clients (id) ON DELETE CASCADE;

CREATE UNIQUE INDEX IF NOT EXISTS uq_embedded_pending_unverified_email
    ON auth.embedded_pending_registrations (tenant_id, oauth_client_row_id, lower(trim(both from email)))
    WHERE email_verified_at IS NULL;
