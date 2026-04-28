-- Per-OAuth-client overrides for access/refresh JWT lifetimes (NULL = use server AUTH__* defaults).
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS access_ttl_seconds INTEGER NULL;
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS refresh_ttl_seconds INTEGER NULL;

ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_access_ttl_seconds_check;
ALTER TABLE clients ADD CONSTRAINT clients_access_ttl_seconds_check
    CHECK (access_ttl_seconds IS NULL OR (access_ttl_seconds >= 60 AND access_ttl_seconds <= 86400));

ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_refresh_ttl_seconds_check;
ALTER TABLE clients ADD CONSTRAINT clients_refresh_ttl_seconds_check
    CHECK (refresh_ttl_seconds IS NULL OR (refresh_ttl_seconds >= 300 AND refresh_ttl_seconds <= 7776000));

ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_token_ttl_pair_check;
ALTER TABLE clients ADD CONSTRAINT clients_token_ttl_pair_check
    CHECK (
        access_ttl_seconds IS NULL
        OR refresh_ttl_seconds IS NULL
        OR refresh_ttl_seconds >= access_ttl_seconds
    );
