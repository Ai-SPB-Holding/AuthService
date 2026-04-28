-- True multi-tenant: drop global uniqueness of OAuth public client_id (per-tenant UNIQUE remains from 0001).
-- Case-normalized email per tenant via generated column + unique index.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM users u
        GROUP BY u.tenant_id, lower(trim(both from u.email))
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION
            'Migration 0015: duplicate users in the same tenant after lower(trim(email)); resolve duplicates before migrating';
    END IF;
END $$;

DROP INDEX IF EXISTS uq_clients_client_id;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_id_email_key;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_norm TEXT
    GENERATED ALWAYS AS (lower(trim(both from email))) STORED;

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_tenant_email_norm ON users (tenant_id, email_norm);
