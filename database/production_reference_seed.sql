-- PROJECT CHIMERA production reference data only.
-- Safe to rerun: existing identifiers/paths/hashes are left unchanged.
-- Contains no users, credentials, documents, activity, telemetry, sessions, events, or history.

START TRANSACTION;

INSERT INTO decoy_endpoints (decoy_identifier, path, name, type, is_active, risk_weight, response_mode)
SELECT 'DEC-ADMIN-OLD', '/admin-old', 'Legacy Administration', 'WEB_ROUTE', 1, 25, 'BELIEVABLE_403'
WHERE NOT EXISTS (SELECT 1 FROM decoy_endpoints WHERE decoy_identifier='DEC-ADMIN-OLD' OR path='/admin-old');
INSERT INTO decoy_endpoints (decoy_identifier, path, name, type, is_active, risk_weight, response_mode)
SELECT 'DEC-INTERNAL', '/internal', 'Internal Portal', 'WEB_ROUTE', 1, 30, 'SYNTHETIC_LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM decoy_endpoints WHERE decoy_identifier='DEC-INTERNAL' OR path='/internal');
INSERT INTO decoy_endpoints (decoy_identifier, path, name, type, is_active, risk_weight, response_mode)
SELECT 'DEC-API-DEBUG', '/api/debug', 'Debug API', 'API_ROUTE', 1, 35, 'SYNTHETIC_JSON'
WHERE NOT EXISTS (SELECT 1 FROM decoy_endpoints WHERE decoy_identifier='DEC-API-DEBUG' OR path='/api/debug');

INSERT INTO honeytokens (token_identifier, description, token_hash, is_active, risk_weight)
SELECT 'HT-BACKUP-001', 'Synthetic backup reference. No external access.', SHA2('CHM_HONEY_HT_BACKUP_001',256), 1, 55
WHERE NOT EXISTS (SELECT 1 FROM honeytokens WHERE token_identifier='HT-BACKUP-001' OR token_hash=SHA2('CHM_HONEY_HT_BACKUP_001',256));
INSERT INTO honeytokens (token_identifier, description, token_hash, is_active, risk_weight)
SELECT 'HT-API-001', 'Synthetic API identifier. No external access.', SHA2('CHM_HONEY_HT_API_001',256), 1, 60
WHERE NOT EXISTS (SELECT 1 FROM honeytokens WHERE token_identifier='HT-API-001' OR token_hash=SHA2('CHM_HONEY_HT_API_001',256));

INSERT INTO vulnerability_modules (vulnerability_identifier,name,description,affected_component,expected_attack_surface,learning_objective,expected_impact,mitigation,state,is_active)
SELECT 'CHIM-VULN-001','Controlled Broken Object Authorization','Synthetic object lookup demonstrating missing versus enforced ownership.','/lab/idor','GET requests using LAB-prefixed synthetic object identifiers.','Compare predictable cross-object access with an owner-bound lookup.','Read-only exposure of another synthetic lab identity record.','Require the synthetic actor owner to match the requested lab object.','REMEDIATED',1
WHERE NOT EXISTS (SELECT 1 FROM vulnerability_modules WHERE vulnerability_identifier='CHIM-VULN-001');
INSERT INTO vulnerability_modules (vulnerability_identifier,name,description,affected_component,expected_attack_surface,learning_objective,expected_impact,mitigation,state,is_active)
SELECT 'CHIM-VULN-002','Controlled SQL Injection','Bounded SQL predicate demonstration over an inline synthetic derived dataset.','/lab/sqli','GET search input using a restricted non-stacked predicate grammar.','Compare string concatenation with a bound prepared parameter.','Read-only retrieval of additional inline synthetic rows.','Use a prepared statement and bind the exact archive code.','REMEDIATED',1
WHERE NOT EXISTS (SELECT 1 FROM vulnerability_modules WHERE vulnerability_identifier='CHIM-VULN-002');
INSERT INTO vulnerability_modules (vulnerability_identifier,name,description,affected_component,expected_attack_surface,learning_objective,expected_impact,mitigation,state,is_active)
SELECT 'CHIM-VULN-003','Controlled Reflected XSS','Non-persistent reflection inside a standalone opaque-origin CSP sandbox.','/lab/xss','GET input reflected only by the isolated lab response.','Compare raw reflection with contextual HTML escaping.','Script execution is confined to a sandboxed lab document with no same-origin access.','Encode reflected content with htmlspecialchars before rendering.','REMEDIATED',1
WHERE NOT EXISTS (SELECT 1 FROM vulnerability_modules WHERE vulnerability_identifier='CHIM-VULN-003');

COMMIT;

-- Expected after first import into a clean schema:
-- decoy_endpoints=3, honeytokens=2, vulnerability_modules=3; operational tables remain empty.
