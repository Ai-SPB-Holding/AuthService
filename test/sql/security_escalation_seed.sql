-- Idempotent probe user for security-admin-escalation (no admin role).
-- Password: EscalationProbe2026!Secure (Argon2id m=19456 t=2 p=1; matches backend/src/security/password.rs)
-- Tenant / user UUIDs are fixed so the harness does not collide with dashboard demo seeds.

BEGIN;

INSERT INTO users (
    id,
    tenant_id,
    email,
    is_active,
    is_locked,
    email_verified,
    registration_source
) VALUES (
    'b1111111-1111-1111-1111-111111111111',
    'a1111111-1111-1111-1111-111111111111',
    'security-escalation-probe@authservice.local',
    TRUE,
    FALSE,
    TRUE,
    'security-harness'
)
ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    is_active = TRUE,
    is_locked = FALSE,
    email_verified = TRUE;

INSERT INTO credentials (user_id, tenant_id, password_hash)
VALUES (
    'b1111111-1111-1111-1111-111111111111',
    'a1111111-1111-1111-1111-111111111111',
    '$argon2id$v=19$m=19456,t=2,p=1$jOZW1+L0FdXdHy7VtVMoPQ$aWGXncHsDmXH8aaIkuEIyV+oYu9/JcXSZJ5SKddd54w'
)
ON CONFLICT (user_id, tenant_id) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    updated_at = NOW();

DELETE FROM user_roles ur
USING roles r
WHERE ur.tenant_id = 'a1111111-1111-1111-1111-111111111111'::uuid
  AND ur.user_id = 'b1111111-1111-1111-1111-111111111111'::uuid
  AND ur.role_id = r.id
  AND r.tenant_id = ur.tenant_id
  AND r.name = 'admin';

COMMIT;
