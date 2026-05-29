CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO "roles" (id, name, description) VALUES
(gen_random_uuid(), 'ROLE_ADMIN', 'Full system access with all permissions'),
(gen_random_uuid(), 'ROLE_USER', 'Standard user with limited permissions'),
(gen_random_uuid(), 'ROLE_MANAGER', 'Manages users and projects'),
(gen_random_uuid(), 'ROLE_AUDITOR', 'Read-only access to logs and audits');

INSERT INTO "permissions" (id, name, description) VALUES
(gen_random_uuid(), 'PROFILE_READ', 'Read own profile'),
(gen_random_uuid(), 'PROFILE_UPDATE', 'Update own profile'),
(gen_random_uuid(), 'PASSWORD_CHANGE', 'Change own password'),
(gen_random_uuid(), 'SESSION_READ', 'View own sessions'),
(gen_random_uuid(), 'SESSION_REVOKE', 'Revoke own sessions'),
(gen_random_uuid(), 'USER_READ', 'Read users'),
(gen_random_uuid(), 'USER_CREATE', 'Create users'),
(gen_random_uuid(), 'USER_UPDATE', 'Update users'),
(gen_random_uuid(), 'USER_DELETE', 'Delete users'),
(gen_random_uuid(), 'ROLE_READ', 'Read roles'),
(gen_random_uuid(), 'ROLE_ASSIGN', 'Assign roles'),
(gen_random_uuid(), 'ROLE_CREATE', 'Create roles'),
(gen_random_uuid(), 'ROLE_UPDATE', 'Update roles'),
(gen_random_uuid(), 'ROLE_DELETE', 'Delete roles'),
(gen_random_uuid(), 'PERMISSION_READ', 'Read permissions'),
(gen_random_uuid(), 'PERMISSION_ASSIGN', 'Assign permissions'),
(gen_random_uuid(), 'PROJECT_READ', 'Read projects'),
(gen_random_uuid(), 'PROJECT_CREATE', 'Create projects'),
(gen_random_uuid(), 'PROJECT_EDIT', 'Edit projects'),
(gen_random_uuid(), 'PROJECT_DELETE', 'Delete projects'),
(gen_random_uuid(), 'AUDIT_READ', 'Read audit logs'),
(gen_random_uuid(), 'SYSTEM_SETTINGS_READ', 'Read system settings');

INSERT INTO "obvious_passwords" (id, obvious_pass) VALUES
(gen_random_uuid(), 'password'),
(gen_random_uuid(), 'password1'),
(gen_random_uuid(), 'password123'),
(gen_random_uuid(), 'Password123!'),
(gen_random_uuid(), '12345678'),
(gen_random_uuid(), '123456789'),
(gen_random_uuid(), 'qwerty123'),
(gen_random_uuid(), 'qwerty123!'),
(gen_random_uuid(), 'admin123'),
(gen_random_uuid(), 'admin123!'),
(gen_random_uuid(), 'welcome123'),
(gen_random_uuid(), 'welcome123!'),
(gen_random_uuid(), 'iloveyou123'),
(gen_random_uuid(), 'changeme123'),
(gen_random_uuid(), 'letmein123'),
(gen_random_uuid(), 'abc12345'),
(gen_random_uuid(), 'secure123'),
(gen_random_uuid(), 'test12345')
ON CONFLICT (obvious_pass) DO NOTHING;

INSERT INTO "role_permissions" (role_id, permission_id)
SELECT r.id, p.id
FROM "roles" r
JOIN "permissions" p ON p.name IN (
  'PROFILE_READ',
  'PROFILE_UPDATE',
  'PASSWORD_CHANGE',
  'SESSION_READ',
  'SESSION_REVOKE',
  'PROJECT_READ'
)
WHERE r.name = 'ROLE_USER';

INSERT INTO "role_permissions" (role_id, permission_id)
SELECT r.id, p.id
FROM "roles" r
JOIN "permissions" p ON p.name IN (
  'PROFILE_READ',
  'PROFILE_UPDATE',
  'PASSWORD_CHANGE',
  'SESSION_READ',
  'SESSION_REVOKE',
  'USER_READ',
  'USER_UPDATE',
  'PROJECT_READ',
  'PROJECT_CREATE',
  'PROJECT_EDIT',
  'AUDIT_READ'
)
WHERE r.name = 'ROLE_MANAGER';

INSERT INTO "role_permissions" (role_id, permission_id)
SELECT r.id, p.id
FROM "roles" r
JOIN "permissions" p ON p.name IN (
  'PROFILE_READ',
  'PROFILE_UPDATE',
  'PASSWORD_CHANGE',
  'SESSION_READ',
  'SESSION_REVOKE',
  'USER_READ',
  'USER_CREATE',
  'USER_UPDATE',
  'USER_DELETE',
  'ROLE_READ',
  'ROLE_ASSIGN',
  'ROLE_CREATE',
  'ROLE_UPDATE',
  'ROLE_DELETE',
  'PERMISSION_READ',
  'PROJECT_READ',
  'PROJECT_CREATE',
  'PROJECT_EDIT',
  'PROJECT_DELETE',
  'AUDIT_READ',
  'SYSTEM_SETTINGS_READ'
)
WHERE r.name = 'ROLE_ADMIN';

INSERT INTO "role_permissions" (role_id, permission_id)
SELECT r.id, p.id
FROM "roles" r
JOIN "permissions" p ON p.name IN (
  'AUDIT_READ',
  'USER_READ',
  'ROLE_READ',
  'PERMISSION_READ',
  'SESSION_READ'
)
WHERE r.name = 'ROLE_AUDITOR';

INSERT INTO "users"(
    id, created_at, email, enabled, last_login, name, password_hash, surname, updated_at, username, role_id)
VALUES (
    gen_random_uuid(), 
    now(), 
    'admin@admin.com',
    true, 
    now(), 
    '',
    crypt('admin', gen_salt('bf')), 
    '',
    now(), 
    'admin',
    (SELECT id FROM "roles" WHERE name = 'ROLE_ADMIN')
)
on conflict (username) do nothing;
