-- Remove legacy plaintext client_secret column; confidential clients use client_secret_argon2 only.
ALTER TABLE clients DROP COLUMN IF EXISTS client_secret;
