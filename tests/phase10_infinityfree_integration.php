<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/app/Core/Env.php';
App\Core\Env::load($root . '/.env');

$testDatabase = trim((string) getenv('TEST_DB_DATABASE'));
if ($testDatabase !== 'chimera_test') {
    fwrite(STDERR, "[FAIL] Refusing production-reference integration outside exact chimera_test.\n");
    exit(1);
}
$testUsername = trim((string) getenv('TEST_DB_USERNAME'));
$testPassword = (string) getenv('TEST_DB_PASSWORD');
if ($testUsername === '' || $testPassword === '') {
    fwrite(STDERR, "[FAIL] Dedicated chimera_test credentials are required.\n");
    exit(1);
}
putenv('DB_DATABASE=chimera_test');
$_ENV['DB_DATABASE'] = 'chimera_test';
putenv('DB_USERNAME=' . $testUsername);
$_ENV['DB_USERNAME'] = $testUsername;
putenv('DB_PASSWORD=' . $testPassword);
$_ENV['DB_PASSWORD'] = $testPassword;
require $root . '/bootstrap/app.php';

use App\Core\Database;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$database = Database::connection();
$connection = $database->query('SELECT DATABASE() database_name,@@port server_port,CURRENT_USER() authenticated_user')->fetch();
$safe = is_array($connection)
    && ($connection['database_name'] ?? '') === 'chimera_test'
    && (int) ($connection['server_port'] ?? 0) === 3308
    && str_starts_with((string) ($connection['authenticated_user'] ?? ''), 'chimera_test_app@');
$check($safe, 'Reference-seed integration is isolated to chimera_test on port 3308 with chimera_test_app');
if (!$safe) exit(1);

$sql = (string) file_get_contents(dirname(__DIR__) . '/database/production_reference_seed.sql');
$sql = (string) preg_replace('/^\s*--.*$/m', '', $sql);
$sql = (string) preg_replace('/\b(?:START TRANSACTION|COMMIT)\s*;/i', '', $sql);
$statements = array_values(array_filter(array_map('trim', preg_split('/;\s*(?:\R|$)/', $sql) ?: [])));

$database->beginTransaction();
try {
    $database->exec("DELETE FROM vulnerability_state_changes WHERE vulnerability_module_id IN (SELECT id FROM vulnerability_modules WHERE vulnerability_identifier IN ('CHIM-VULN-001','CHIM-VULN-002','CHIM-VULN-003'))");
    $database->exec("DELETE FROM vulnerability_modules WHERE vulnerability_identifier IN ('CHIM-VULN-001','CHIM-VULN-002','CHIM-VULN-003')");
    $database->exec("DELETE FROM honeytoken_events WHERE honeytoken_id IN (SELECT id FROM honeytokens WHERE token_identifier IN ('HT-BACKUP-001','HT-API-001'))");
    $database->exec("DELETE FROM honeytokens WHERE token_identifier IN ('HT-BACKUP-001','HT-API-001')");
    $database->exec("DELETE FROM decoy_endpoints WHERE decoy_identifier IN ('DEC-ADMIN-OLD','DEC-INTERNAL','DEC-API-DEBUG')");

    foreach ($statements as $statement) $database->exec($statement);
    $counts = [
        'decoys'=>(int)$database->query("SELECT COUNT(*) FROM decoy_endpoints WHERE decoy_identifier IN ('DEC-ADMIN-OLD','DEC-INTERNAL','DEC-API-DEBUG')")->fetchColumn(),
        'tokens'=>(int)$database->query("SELECT COUNT(*) FROM honeytokens WHERE token_identifier IN ('HT-BACKUP-001','HT-API-001')")->fetchColumn(),
        'modules'=>(int)$database->query("SELECT COUNT(*) FROM vulnerability_modules WHERE vulnerability_identifier IN ('CHIM-VULN-001','CHIM-VULN-002','CHIM-VULN-003')")->fetchColumn(),
    ];
    $check($counts === ['decoys'=>3,'tokens'=>2,'modules'=>3], 'First production-reference import creates exactly eight registry rows');
    $check((int)$database->query("SELECT COUNT(*) FROM vulnerability_modules WHERE vulnerability_identifier LIKE 'CHIM-VULN-%' AND state='REMEDIATED'")->fetchColumn() === 3, 'Imported vulnerability modules are REMEDIATED');

    foreach ($statements as $statement) $database->exec($statement);
    $repeat = (int)$database->query("SELECT (SELECT COUNT(*) FROM decoy_endpoints WHERE decoy_identifier IN ('DEC-ADMIN-OLD','DEC-INTERNAL','DEC-API-DEBUG'))+(SELECT COUNT(*) FROM honeytokens WHERE token_identifier IN ('HT-BACKUP-001','HT-API-001'))+(SELECT COUNT(*) FROM vulnerability_modules WHERE vulnerability_identifier IN ('CHIM-VULN-001','CHIM-VULN-002','CHIM-VULN-003'))")->fetchColumn();
    $check($repeat === 8, 'Repeated production-reference import remains exactly eight rows');

    $database->exec("UPDATE vulnerability_modules SET state='VULNERABLE' WHERE vulnerability_identifier='CHIM-VULN-001'");
    foreach ($statements as $statement) $database->exec($statement);
    $state = (string)$database->query("SELECT state FROM vulnerability_modules WHERE vulnerability_identifier='CHIM-VULN-001'")->fetchColumn();
    $check($state === 'VULNERABLE', 'Idempotent seed does not overwrite an existing operational module state');
    $check((int)$database->query('SELECT COUNT(*) FROM users')->fetchColumn() === 0, 'Reference import creates no users in the unseeded test database');
    $check((int)$database->query('SELECT COUNT(*) FROM security_events')->fetchColumn() === 0, 'Reference import creates no telemetry in the test database');
    $check((int)$database->query('SELECT COUNT(*) FROM security_sessions')->fetchColumn() === 0, 'Reference import creates no security sessions in the test database');
} finally {
    if ($database->inTransaction()) $database->rollBack();
}

$remaining = (int)$database->query("SELECT (SELECT COUNT(*) FROM decoy_endpoints WHERE decoy_identifier IN ('DEC-ADMIN-OLD','DEC-INTERNAL','DEC-API-DEBUG'))+(SELECT COUNT(*) FROM honeytokens WHERE token_identifier IN ('HT-BACKUP-001','HT-API-001'))+(SELECT COUNT(*) FROM vulnerability_modules WHERE vulnerability_identifier IN ('CHIM-VULN-001','CHIM-VULN-002','CHIM-VULN-003'))")->fetchColumn();
$check($remaining === 0, 'Reference-seed integration rollback leaves no registry fixtures');

echo "\n{$passed} InfinityFree reference integration checks passed, {$failed} failed.\n";
exit($failed === 0 ? 0 : 1);
