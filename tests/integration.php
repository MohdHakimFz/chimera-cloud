<?php

declare(strict_types=1);

$testRoot = dirname(__DIR__);
require $testRoot . '/app/Core/Env.php';
\App\Core\Env::load($testRoot . '/.env');

$testDatabase = trim((string) getenv('TEST_DB_DATABASE'));
if ($testDatabase === '') {
    echo "[SKIP] DATABASE UNAVAILABLE: TEST_DB_DATABASE is not configured.\n";
    exit(0);
}

if ($testDatabase !== 'chimera_test') {
    echo "[FAIL] TEST_DB_DATABASE must be exactly chimera_test. Refusing destructive integration testing.\n";
    exit(1);
}

$developmentDatabase = trim((string) getenv('DB_DATABASE'));
if ($developmentDatabase !== 'chimera') {
    echo "[FAIL] DB_DATABASE must be exactly chimera for this local verification checkpoint.\n";
    exit(1);
}

$testUsername = trim((string) getenv('TEST_DB_USERNAME'));
$testPassword = (string) getenv('TEST_DB_PASSWORD');
if ($testUsername === '' || $testPassword === '') {
    echo "[SKIP] DATABASE UNAVAILABLE: dedicated test credentials are not configured.\n";
    exit(0);
}

putenv('DB_DATABASE=' . $testDatabase);
$_ENV['DB_DATABASE'] = $testDatabase;
putenv('DB_USERNAME=' . $testUsername);
$_ENV['DB_USERNAME'] = $testUsername;
putenv('DB_PASSWORD=' . $testPassword);
$_ENV['DB_PASSWORD'] = $testPassword;
$app = require $testRoot . '/bootstrap/app.php';

use App\Core\Database;
use App\Models\Activity;
use App\Models\Document;

try {
    $database = Database::connection();
    $connection = $database->query('SELECT DATABASE() AS database_name, @@port AS server_port, VERSION() AS server_version, CURRENT_USER() AS authenticated_user')->fetch();
    if (($connection['database_name'] ?? '') !== 'chimera_test' || (int) ($connection['server_port'] ?? 0) !== 3308 || !str_starts_with((string) ($connection['authenticated_user'] ?? ''), 'chimera_test_app@') || !str_starts_with((string) ($connection['server_version'] ?? ''), '12.2.2-MariaDB')) {
        echo "[FAIL] Integration connection is not isolated to chimera_test on port 3308 with chimera_test_app.\n";
        exit(1);
    }
    echo "[PASS] Integration connection uses MariaDB 12.2.2 on port 3308 with chimera_test_app and chimera_test\n";
    $database->query('SELECT 1 FROM users LIMIT 1');
    $database->query('SELECT 1 FROM documents LIMIT 1');
    $database->query('SELECT 1 FROM user_activity LIMIT 1');
    $expectedTables = [
        'decoy_endpoints', 'documents', 'honeytoken_events', 'honeytokens', 'security_events',
        'security_score_contributors', 'security_sessions', 'user_activity', 'users',
        'vulnerability_modules', 'vulnerability_state_changes',
    ];
    $tableStatement = $database->prepare('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = :schema ORDER BY TABLE_NAME');
    $tableStatement->execute(['schema' => 'chimera_test']);
    $actualTestTables = array_column($tableStatement->fetchAll(), 'TABLE_NAME');
    $testTableSetMatches = count($actualTestTables) === count($expectedTables)
        && array_diff($expectedTables, $actualTestTables) === []
        && array_diff($actualTestTables, $expectedTables) === [];
    if (!$testTableSetMatches) {
        echo "[FAIL] Integration database does not contain exactly the 11 expected tables.\n";
        echo '[INFO] Integration table metadata returned: ' . json_encode($actualTestTables, JSON_UNESCAPED_SLASHES) . "\n";
        exit(1);
    }
    echo "[PASS] Integration database contains exactly the 11 expected tables\n";
    $expectedIndexes = [
        'uq_users_email', 'idx_users_role_active', 'uq_documents_storage_name', 'idx_documents_owner_created',
        'idx_activity_user_created', 'idx_activity_type_created', 'uq_security_sessions_identifier',
        'idx_security_sessions_risk', 'idx_security_sessions_last_seen', 'idx_score_session_created',
        'uq_decoys_identifier', 'uq_decoys_path', 'idx_decoys_active', 'uq_honeytokens_identifier',
        'uq_honeytokens_hash', 'idx_honeytokens_active', 'uq_vulnerability_identifier',
        'idx_vulnerability_state', 'idx_events_session_created', 'idx_events_type_created',
        'idx_events_severity_created', 'uq_honeytoken_security_event', 'idx_state_changes_module_created',
    ];
    $indexStatement = $database->query("SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = 'chimera_test' AND INDEX_NAME <> 'PRIMARY'");
    $actualIndexes = array_column($indexStatement->fetchAll(), 'INDEX_NAME');
    $expectedForeignKeys = [
        'fk_documents_user', 'fk_activity_user', 'fk_security_sessions_user', 'fk_score_session',
        'fk_events_session', 'fk_honeytoken_events_token', 'fk_honeytoken_events_event',
        'fk_state_changes_module', 'fk_state_changes_user',
    ];
    $foreignKeyStatement = $database->query("SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = 'chimera_test' AND CONSTRAINT_TYPE = 'FOREIGN KEY'");
    $actualForeignKeys = array_column($foreignKeyStatement->fetchAll(), 'CONSTRAINT_NAME');
    if (array_diff($expectedIndexes, $actualIndexes) !== [] || array_diff($expectedForeignKeys, $actualForeignKeys) !== []) {
        echo "[FAIL] Integration database is missing expected indexes or foreign keys.\n";
        exit(1);
    }
    echo "[PASS] Integration database contains the expected indexes and foreign keys\n";
    if ((int) $database->query("SELECT COUNT(*) FROM users WHERE email IN ('user@chimera.test','admin@chimera.test','security@chimera.test')")->fetchColumn() !== 0) {
        echo "[FAIL] Integration database unexpectedly contains development seed accounts.\n";
        exit(1);
    }
    echo "[PASS] Integration database remains isolated from development seed data\n";
    if ((int) $database->query("SELECT COUNT(*) FROM users WHERE email LIKE '%@e2e.chimera.test'")->fetchColumn() !== 0) {
        echo "[FAIL] Integration database contains residual HTTP E2E fixtures.\n";
        exit(1);
    }
    echo "[PASS] Integration database contains no residual HTTP E2E fixtures\n";
    if ((int) $database->query('SELECT (SELECT COUNT(*) FROM decoy_endpoints) + (SELECT COUNT(*) FROM honeytokens) + (SELECT COUNT(*) FROM honeytoken_events) + (SELECT COUNT(*) FROM security_events) + (SELECT COUNT(*) FROM security_sessions) + (SELECT COUNT(*) FROM security_score_contributors) + (SELECT COUNT(*) FROM vulnerability_modules) + (SELECT COUNT(*) FROM vulnerability_state_changes)')->fetchColumn() !== 0) {
        echo "[FAIL] Integration database contains residual telemetry, deception, or lab E2E records.\n";
        exit(1);
    }
    echo "[PASS] Integration database contains no residual telemetry, deception, or lab E2E records\n";
    $grants = $database->query('SHOW GRANTS FOR CURRENT_USER')->fetchAll(PDO::FETCH_COLUMN);
    $grantText = implode("\n", $grants);
    if (!str_contains($grantText, '`chimera_test`.*') || str_contains($grantText, '`chimera`.*') || preg_match('/GRANT (?!USAGE)[^\n]+ ON \*\.\*/i', $grantText) || preg_match('/\b(SUPER|FILE|PROCESS|SHUTDOWN|CREATE USER|GRANT OPTION|RELOAD)\b/i', $grantText)) {
        echo "[FAIL] Test account privileges are not isolated to chimera_test.\n";
        exit(1);
    }
    echo "[PASS] Test account grants are database-scoped and exclude prohibited administrative privileges\n";
} catch (Throwable $exception) {
    echo '[FAIL] Dedicated test database connection or schema verification failed: ' . $exception->getMessage() . "\n";
    exit(1);
}

$database->beginTransaction();
try {
    $suffix = bin2hex(random_bytes(6));
    $insertUser = $database->prepare('INSERT INTO users (name, email, password_hash, role, is_active) VALUES (:name, :email, :password_hash, :role, 1)');
    $insertUser->execute(['name' => 'Owner A', 'email' => "owner-a-{$suffix}@chimera.test", 'password_hash' => password_hash('TestPassword!2026', PASSWORD_DEFAULT), 'role' => 'user']);
    $ownerA = (int) $database->lastInsertId();
    $insertUser->execute(['name' => 'Owner B', 'email' => "owner-b-{$suffix}@chimera.test", 'password_hash' => password_hash('TestPassword!2026', PASSWORD_DEFAULT), 'role' => 'user']);
    $ownerB = (int) $database->lastInsertId();

    $insertDocument = $database->prepare('INSERT INTO documents (user_id, original_name, storage_name, mime_type, size_bytes, checksum_sha256) VALUES (:user_id, :original_name, :storage_name, :mime_type, 4, :checksum)');
    $insertDocument->execute(['user_id' => $ownerA, 'original_name' => 'owner-a.txt', 'storage_name' => str_repeat('a', 48) . '.txt', 'mime_type' => 'text/plain', 'checksum' => hash('sha256', 'test')]);
    $documentA = (int) $database->lastInsertId();
    $insertDocument->execute(['user_id' => $ownerB, 'original_name' => 'owner-b.txt', 'storage_name' => str_repeat('b', 48) . '.txt', 'mime_type' => 'text/plain', 'checksum' => hash('sha256', 'test')]);
    $documentB = (int) $database->lastInsertId();

    $passes = 0;
    $failures = 0;
    $assert = static function (bool $condition, string $label) use (&$passes, &$failures): void {
        if ($condition) {
            $passes++;
            echo "[PASS] {$label}\n";
        } else {
            $failures++;
            echo "[FAIL] {$label}\n";
        }
    };

    $assert(Document::findOwned($documentA, $ownerA) !== null, 'User A can retrieve Document A');
    $assert(Document::findOwned($documentB, $ownerB) !== null, 'User B can retrieve Document B');
    $assert(Document::findOwned($documentB, $ownerA) === null, 'User A cannot retrieve Document B owned by User B');
    $assert(Document::findOwned($documentA, $ownerB) === null, 'User B cannot retrieve Document A owned by User A');
    $ownerAList = Document::allForUser($ownerA);
    $ownerBList = Document::allForUser($ownerB);
    $assert(count($ownerAList) === 1 && (int) $ownerAList[0]['id'] === $documentA, 'User A listing contains only Document A');
    $assert(count($ownerBList) === 1 && (int) $ownerBList[0]['id'] === $documentB, 'User B listing contains only Document B');
    Activity::record($ownerA, 'INTEGRATION_TEST', 'Owner A activity.');
    Activity::record($ownerB, 'INTEGRATION_TEST', 'Owner B activity.');
    $ownerAActivity = Activity::recentForUser($ownerA, 10);
    $assert(count($ownerAActivity) === 1 && $ownerAActivity[0]['description'] === 'Owner A activity.', 'Activity history does not expose another user activity');
    $assert(count(Activity::recentForUser($ownerB, 10)) === 1, 'User B activity history remains independently scoped');

    echo "\n{$passes} database integration checks passed, {$failures} failed.\n";
    $database->rollBack();
    exit($failures === 0 ? 0 : 1);
} catch (Throwable $exception) {
    if ($database->inTransaction()) {
        $database->rollBack();
    }
    echo '[FAIL] Database integration test error: ' . $exception->getMessage() . "\n";
    exit(1);
}
