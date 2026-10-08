<?php

declare(strict_types=1);

$app = require dirname(__DIR__) . '/bootstrap/app.php';

use App\Core\Database;

$passes = 0;
$failures = 0;
$check = static function (bool $condition, string $label) use (&$passes, &$failures): void {
    if ($condition) {
        $passes++;
        echo "[PASS] {$label}\n";
    } else {
        $failures++;
        echo "[FAIL] {$label}\n";
    }
};

try {
    $database = Database::connection();
    $connection = $database->query(
        'SELECT DATABASE() AS database_name, @@port AS server_port, VERSION() AS server_version, CURRENT_USER() AS authenticated_user'
    )->fetch();
} catch (Throwable $exception) {
    echo '[FAIL] Development database connection failed: ' . $exception->getMessage() . "\n";
    exit(1);
}

$check((string) env('DB_HOST') === '127.0.0.1', 'Configured development host is 127.0.0.1');
$check((string) env('DB_PORT') === '3308' && (int) $connection['server_port'] === 3308, 'Configured and connected development port is 3308');
$check($connection['database_name'] === 'chimera', 'Connected development database is chimera');
$check(str_starts_with((string) $connection['server_version'], '12.2.2-MariaDB'), 'Database server reports MariaDB 12.2.2');
$check(str_starts_with((string) $connection['authenticated_user'], 'chimera_app@'), 'Application connection uses chimera_app rather than root');

$expectedTables = [
    'decoy_endpoints', 'documents', 'honeytoken_events', 'honeytokens', 'security_events',
    'security_score_contributors', 'security_sessions', 'user_activity', 'users',
    'vulnerability_modules', 'vulnerability_state_changes',
];
$tableStatement = $database->prepare('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = :schema ORDER BY TABLE_NAME');
$tableStatement->execute(['schema' => 'chimera']);
$actualTables = array_column($tableStatement->fetchAll(), 'TABLE_NAME');
$tableSetMatches = count($actualTables) === count($expectedTables)
    && array_diff($expectedTables, $actualTables) === []
    && array_diff($actualTables, $expectedTables) === [];
$check($tableSetMatches, 'Development database contains exactly the 11 expected tables');
if (!$tableSetMatches) {
    echo '[INFO] Development table metadata returned: ' . json_encode($actualTables, JSON_UNESCAPED_SLASHES) . "\n";
}

$expectedIndexes = [
    'uq_users_email', 'idx_users_role_active', 'uq_documents_storage_name', 'idx_documents_owner_created',
    'idx_activity_user_created', 'idx_activity_type_created', 'uq_security_sessions_identifier',
    'idx_security_sessions_risk', 'idx_security_sessions_last_seen', 'idx_score_session_created',
    'uq_decoys_identifier', 'uq_decoys_path', 'idx_decoys_active', 'uq_honeytokens_identifier',
    'uq_honeytokens_hash', 'idx_honeytokens_active', 'uq_vulnerability_identifier',
    'idx_vulnerability_state', 'idx_events_session_created', 'idx_events_type_created',
    'idx_events_severity_created', 'uq_honeytoken_security_event', 'idx_state_changes_module_created',
];
$indexStatement = $database->prepare("SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = :schema AND INDEX_NAME <> 'PRIMARY'");
$indexStatement->execute(['schema' => 'chimera']);
$actualIndexes = array_column($indexStatement->fetchAll(), 'INDEX_NAME');
$check(array_diff($expectedIndexes, $actualIndexes) === [], 'Expected unique and lookup indexes are present');

$expectedForeignKeys = [
    'fk_documents_user', 'fk_activity_user', 'fk_security_sessions_user', 'fk_score_session',
    'fk_events_session', 'fk_honeytoken_events_token', 'fk_honeytoken_events_event',
    'fk_state_changes_module', 'fk_state_changes_user',
];
$foreignKeyStatement = $database->prepare(
    "SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = :schema AND CONSTRAINT_TYPE = 'FOREIGN KEY'"
);
$foreignKeyStatement->execute(['schema' => 'chimera']);
$actualForeignKeys = array_column($foreignKeyStatement->fetchAll(), 'CONSTRAINT_NAME');
$check(array_diff($expectedForeignKeys, $actualForeignKeys) === [], 'Expected foreign-key relationships are present');

$seedUsers = $database->query(
    "SELECT role, COUNT(*) AS total FROM users WHERE email IN ('user@chimera.test','admin@chimera.test','security@chimera.test') GROUP BY role"
)->fetchAll();
$roleCounts = array_fill_keys(['user', 'admin', 'security_admin'], 0);
foreach ($seedUsers as $row) {
    $roleCounts[$row['role']] = (int) $row['total'];
}
$check($roleCounts === ['user' => 1, 'admin' => 1, 'security_admin' => 1], 'Synthetic seed contains one account for each role');
$check((int) $database->query('SELECT COUNT(*) FROM decoy_endpoints')->fetchColumn() === 3, 'Synthetic decoy configuration seed count is 3');
$check((int) $database->query("SELECT COUNT(*) FROM decoy_endpoints WHERE is_active = 1 AND ((path = '/admin-old' AND response_mode = 'BELIEVABLE_403') OR (path = '/internal' AND response_mode = 'SYNTHETIC_LOGIN') OR (path = '/api/debug' AND response_mode = 'SYNTHETIC_JSON'))")->fetchColumn() === 3, 'Phase 4 decoy paths and response modes match the static policy');
$check((int) $database->query('SELECT COUNT(*) FROM honeytokens')->fetchColumn() === 2, 'Synthetic honeytoken configuration seed count is 2');
$check((int) $database->query("SELECT COUNT(*) FROM honeytokens WHERE (token_identifier = 'HT-BACKUP-001' AND token_hash = SHA2('CHM_HONEY_HT_BACKUP_001', 256)) OR (token_identifier = 'HT-API-001' AND token_hash = SHA2('CHM_HONEY_HT_API_001', 256))")->fetchColumn() === 2, 'Honeytoken seed hashes use the CHIMERA-only synthetic format');
$check((int) $database->query('SELECT COUNT(*) FROM vulnerability_modules')->fetchColumn() === 3, 'Synthetic vulnerability registry seed count is 3');
$check((int) $database->query("SELECT COUNT(*) FROM vulnerability_modules WHERE is_active=1 AND ((vulnerability_identifier='CHIM-VULN-001' AND affected_component='/lab/idor') OR (vulnerability_identifier='CHIM-VULN-002' AND affected_component='/lab/sqli') OR (vulnerability_identifier='CHIM-VULN-003' AND affected_component='/lab/xss'))")->fetchColumn() === 3, 'Controlled lab registry contains only the three expected active modules');
$check((int) $database->query("SELECT COUNT(*) FROM user_activity WHERE activity_type = 'ACCOUNT_CREATED'")->fetchColumn() >= 3, 'Synthetic account-created activity seed is present');
$developmentFixtureCount = (int) $database->query("SELECT COUNT(*) FROM users WHERE email LIKE '%@e2e.chimera.test'")->fetchColumn();
$check($developmentFixtureCount === 0, 'Development database contains no HTTP E2E fixture accounts');
if ($developmentFixtureCount !== 0) {
    echo "[INFO] {$developmentFixtureCount} synthetic HTTP E2E fixture account(s) remain in chimera; no development data was deleted.\n";
}

$grants = $database->query('SHOW GRANTS FOR CURRENT_USER')->fetchAll(PDO::FETCH_COLUMN);
$grantText = implode("\n", $grants);
$check(str_contains($grantText, '`chimera`.*'), 'Application grant is scoped to the chimera database');
$check(!str_contains($grantText, '`chimera_test`.*'), 'Application account has no grant on chimera_test');
$check(!preg_match('/GRANT (?!USAGE)[^\n]+ ON \*\.\*/i', $grantText), 'Application account has no global privileges beyond USAGE');
$check(!preg_match('/\b(SUPER|FILE|PROCESS|SHUTDOWN|CREATE USER|GRANT OPTION|RELOAD)\b/i', $grantText), 'Application account has no prohibited administrative privileges');

echo "\n{$passes} development database checks passed, {$failures} failed.\n";
exit($failures === 0 ? 0 : 1);
