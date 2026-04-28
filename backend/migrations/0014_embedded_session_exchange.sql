-- One-time codes for iframe → BFF token exchange (see `/api/session-code` + `embedded_session` grant on `/oauth2/token`).
CREATE TABLE IF NOT EXISTS embedded_exchange_codes (
    code TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    oauth_client_public_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_embedded_exchange_expires
    ON embedded_exchange_codes (expires_at)
    WHERE NOT consumed;
