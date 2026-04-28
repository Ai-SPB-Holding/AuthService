-- Users explicitly allowed to access auth-service settings API (non-admin delegates).
CREATE TABLE IF NOT EXISTS client_user_membership (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    client_id UUID NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id, client_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_client_user_membership_user
    ON client_user_membership (tenant_id, user_id);
