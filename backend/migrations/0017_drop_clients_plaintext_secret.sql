-- Remove legacy plaintext client_secret column; confidential clients use client_secret_argon2 only.
CREATE SCHEMA IF NOT EXISTS auth;

ALTER TABLE auth.clients DROP COLUMN IF EXISTS client_secret;
