-- Optional v2 postMessage protocol + validated UI theme JSON (design tokens)
CREATE SCHEMA IF NOT EXISTS auth;

ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS embedded_protocol_v2 BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS embedded_ui_theme JSONB;

COMMENT ON COLUMN auth.clients.embedded_protocol_v2 IS 'When true, /embedded-login uses protocol v1 envelope (v, type, ts, source, nonce) and INIT/EMBED_READY handshakes; legacy messages unchanged when false.';
COMMENT ON COLUMN auth.clients.embedded_ui_theme IS 'Whitelisted design tokens (JSON); validated on write and by iframe at runtime.';
