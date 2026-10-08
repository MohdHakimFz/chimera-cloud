-- Synthetic laboratory seed data only.
-- Change all seeded passwords before any internet-accessible deployment.

INSERT INTO users (name, email, password_hash, role, is_active) VALUES
('Amina Rahman', 'user@chimera.test', '$2y$10$cVxwI/fbDDwDJXWN0U6.U.XbMH9A7WQIDG8W8heMINr8saCY22VLO', 'user', 1),
('Darren Lim', 'admin@chimera.test', '$2y$10$EzpB/a5iHFpc84J2LSrq4e/F3tUd7APuqGcR98Rh1rR9AR1s52O4S', 'admin', 1),
('Nadia Iskandar', 'security@chimera.test', '$2y$10$4JZyaPH2RjVZbZ/hNKSLhegFzlvGco7iscdRZD1DdPgaVGxKyHn9O', 'security_admin', 1);

INSERT INTO user_activity (user_id, activity_type, description)
SELECT id, 'ACCOUNT_CREATED', 'Synthetic seed account created.' FROM users
WHERE email IN ('user@chimera.test', 'admin@chimera.test', 'security@chimera.test');

INSERT INTO decoy_endpoints (decoy_identifier, path, name, type, is_active, risk_weight, response_mode) VALUES
('DEC-ADMIN-OLD', '/admin-old', 'Legacy Administration', 'WEB_ROUTE', 1, 25, 'BELIEVABLE_403'),
('DEC-INTERNAL', '/internal', 'Internal Portal', 'WEB_ROUTE', 1, 30, 'SYNTHETIC_LOGIN'),
('DEC-API-DEBUG', '/api/debug', 'Debug API', 'API_ROUTE', 1, 35, 'SYNTHETIC_JSON');

INSERT INTO honeytokens (token_identifier, description, token_hash, is_active, risk_weight) VALUES
('HT-BACKUP-001', 'Synthetic backup reference. No external access.', SHA2('CHM_HONEY_HT_BACKUP_001', 256), 1, 55),
('HT-API-001', 'Synthetic API identifier. No external access.', SHA2('CHM_HONEY_HT_API_001', 256), 1, 60);

INSERT INTO vulnerability_modules (
    vulnerability_identifier, name, description, affected_component, expected_attack_surface,
    learning_objective, expected_impact, mitigation, state, is_active
) VALUES
(
    'CHIM-VULN-001', 'Controlled Broken Object Authorization',
    'Synthetic object lookup demonstrating missing versus enforced ownership.', '/lab/idor',
    'GET requests using LAB-prefixed synthetic object identifiers.',
    'Compare predictable cross-object access with an owner-bound lookup.',
    'Read-only exposure of another synthetic lab identity record.',
    'Require the synthetic actor owner to match the requested lab object.', 'VULNERABLE', 1
),
(
    'CHIM-VULN-002', 'Controlled SQL Injection',
    'Bounded SQL predicate demonstration over an inline synthetic derived dataset.', '/lab/sqli',
    'GET search input using a restricted non-stacked predicate grammar.',
    'Compare string concatenation with a bound prepared parameter.',
    'Read-only retrieval of additional inline synthetic rows.',
    'Use a prepared statement and bind the exact archive code.', 'VULNERABLE', 1
),
(
    'CHIM-VULN-003', 'Controlled Reflected XSS',
    'Non-persistent reflection inside a standalone opaque-origin CSP sandbox.', '/lab/xss',
    'GET input reflected only by the isolated lab response.',
    'Compare raw reflection with contextual HTML escaping.',
    'Script execution is confined to a sandboxed lab document with no same-origin access.',
    'Encode reflected content with htmlspecialchars before rendering.', 'VULNERABLE', 1
);
