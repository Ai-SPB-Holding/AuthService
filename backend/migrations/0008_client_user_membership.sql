-- Users explicitly allowed to access auth-service settings API (non-admin delegates).
CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE IF NOT EXISTS auth.client_user_membership (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    client_id UUID NOT NULL REFERENCES auth.clients (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id, client_id),
    FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_client_user_membership_user
    ON auth.client_user_membership (tenant_id, user_id);
