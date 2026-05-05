-- OAuth client metadata
CREATE SCHEMA IF NOT EXISTS auth;

ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS scopes TEXT NOT NULL DEFAULT 'openid profile email';
ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS allowed_redirect_uris JSONB;

-- Backfill JSON array from existing single redirect_uri
UPDATE auth.clients
SET allowed_redirect_uris = to_jsonb(ARRAY[redirect_uri])
WHERE allowed_redirect_uris IS NULL;

-- Admin + API audit trail (separate from auth_events)
CREATE TABLE IF NOT EXISTS auth.audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    actor_user_id UUID,
    action TEXT NOT NULL,
    target TEXT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON auth.audit_log (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_refresh_tenant_user ON auth.refresh_tokens (tenant_id, user_id) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS idx_refresh_expires ON auth.refresh_tokens (tenant_id, expires_at DESC) WHERE NOT revoked;
