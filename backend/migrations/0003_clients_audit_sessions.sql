-- OAuth client metadata
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS scopes TEXT NOT NULL DEFAULT 'openid profile email';
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS allowed_redirect_uris JSONB;

-- Backfill JSON array from existing single redirect_uri
UPDATE clients
SET allowed_redirect_uris = to_jsonb(ARRAY[redirect_uri])
WHERE allowed_redirect_uris IS NULL;

-- Admin + API audit trail (separate from auth_events)
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    actor_user_id UUID,
    action TEXT NOT NULL,
    target TEXT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_log (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_refresh_tenant_user ON refresh_tokens (tenant_id, user_id) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens (tenant_id, expires_at DESC) WHERE NOT revoked;
