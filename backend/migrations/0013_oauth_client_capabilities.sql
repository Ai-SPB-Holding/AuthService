-- Per-client OAuth2/OIDC capabilities and nullable client_secret for public clients.
ALTER TABLE clients ALTER COLUMN client_secret DROP NOT NULL;
UPDATE clients SET client_secret = NULL WHERE client_type = 'public' OR TRIM(COALESCE(client_secret, '')) = '';

ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none';
UPDATE clients SET token_endpoint_auth_method = 'client_secret_basic'
    WHERE client_type = 'confidential' AND token_endpoint_auth_method = 'none';

ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token']::TEXT[];
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS response_types TEXT[] NOT NULL DEFAULT ARRAY['code']::TEXT[];
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS require_pkce BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS pkce_methods TEXT[] NOT NULL DEFAULT ARRAY['S256']::TEXT[];
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]'::JSONB;
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS embedded_flow_mode TEXT NOT NULL DEFAULT 'code_exchange';
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS client_jwks_uri TEXT NULL;
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS client_jwks JSONB NULL;
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS default_max_age_seconds INT NULL;
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS use_v2_endpoints_only BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_token_endpoint_auth_method_check;
ALTER TABLE clients ADD CONSTRAINT clients_token_endpoint_auth_method_check
    CHECK (token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt', 'tls_client_auth'));

ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_embedded_flow_mode_check;
ALTER TABLE clients ADD CONSTRAINT clients_embedded_flow_mode_check
    CHECK (embedded_flow_mode IN ('code_exchange', 'bff_cookie', 'legacy_postmessage'));
