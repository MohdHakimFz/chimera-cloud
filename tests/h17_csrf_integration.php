<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/app/Core/Env.php';
App\Core\Env::load($root . '/.env');

if ((string) getenv('TEST_DB_DATABASE') !== 'chimera_test') {
    echo "[FAIL] TEST_DB_DATABASE must be exactly chimera_test." . PHP_EOL;
    exit(1);
}
putenv('DB_DATABASE=chimera_test');
$_ENV['DB_DATABASE'] = 'chimera_test';
putenv('DB_USERNAME=' . (string) getenv('TEST_DB_USERNAME'));
$_ENV['DB_USERNAME'] = (string) getenv('TEST_DB_USERNAME');
putenv('DB_PASSWORD=' . (string) getenv('TEST_DB_PASSWORD'));
$_ENV['DB_PASSWORD'] = (string) getenv('TEST_DB_PASSWORD');
require $root . '/bootstrap/app.php';

use App\Core\Database;
use App\Core\Request;
use App\Services\EvidenceExportService;
use App\Services\SecurityAnalyticsService;
use App\Services\SecurityEventService;
use App\Services\SecuritySessionService;

$database = Database::connection();
$connection = $database->query('SELECT DATABASE() database_name, @@port server_port, CURRENT_USER() authenticated_user')->fetch();
if ($connection['database_name'] !== 'chimera_test' || (int) $connection['server_port'] !== 3308 || !str_starts_with($connection['authenticated_user'], 'chimera_test_app@')) {
    echo "[FAIL] Unsafe H17 integration target." . PHP_EOL;
    exit(1);
}

$tables = ['users','documents','user_activity','security_events','security_sessions','security_score_contributors','vulnerability_state_changes'];
$starts = [];
foreach ($tables as $table) {
    $starts[$table] = (int) $database->query("SELECT COALESCE(MAX(id),0) FROM {$table}")->fetchColumn();
}
$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$sentinel = 'H17_INVALID_TOKEN_SENTINEL_DO_NOT_PERSIST';

try {
    $insertUser = $database->prepare("INSERT INTO users(name,email,password_hash,role,is_active) VALUES('H17 Integration Actor',:email,:password,'user',1)");
    $insertUser->execute(['email' => 'h17-integration-' . bin2hex(random_bytes(5)) . '@test.chimera', 'password' => password_hash('H17-Synthetic!2026', PASSWORD_DEFAULT)]);
    $actorId = (int) $database->lastInsertId();
    $request = new Request('POST', '/profile', [], ['_token' => $sentinel], ['REMOTE_ADDR' => '198.51.100.217', 'HTTP_USER_AGENT' => 'CHIMERA H17 Local Integration'], []);

    $eventIds = [];
    for ($index = 0; $index < 3; $index++) {
        $eventIds[] = SecurityEventService::record($request, 'CSRF_REJECTED', $actorId);
    }
    $ids = implode(',', array_map('intval', $eventIds));
    $events = $database->query("SELECT id,security_session_id,event_type,severity,risk_delta,metadata_json FROM security_events WHERE id IN ({$ids}) ORDER BY id")->fetchAll();
    $check(count($events) === 3, 'Three deliberate CSRF rejections create exactly three security events');
    $check(array_reduce($events, static fn (bool $ok, array $row): bool => $ok && $row['event_type'] === 'CSRF_REJECTED' && $row['severity'] === 'MEDIUM' && (int) $row['risk_delta'] === 12, true), 'Every rejection has CSRF_REJECTED/MEDIUM and exact +12 event delta');
    $metadataValid = true;
    foreach ($events as $event) {
        $metadata = json_decode((string) $event['metadata_json'], true) ?: [];
        $metadataValid = $metadataValid && ($metadata['category'] ?? null) === 'REQUEST_SECURITY' && ($metadata['outcome'] ?? null) === 'REJECTED' && (int) ($metadata['actor_user_id'] ?? 0) === $actorId;
    }
    $check($metadataValid, 'Persisted rejection taxonomy and authenticated actor association are correct');

    $sessionIds = array_values(array_unique(array_map(static fn (array $row): int => (int) $row['security_session_id'], $events)));
    $check(count($sessionIds) === 1 && $sessionIds[0] > 0, 'Repeated authenticated rejections correlate to one bounded actor session');
    $sessionId = $sessionIds[0];
    $session = $database->query("SELECT threat_score,classification,request_count FROM security_sessions WHERE id={$sessionId}")->fetch();
    $check((int) $session['threat_score'] === 36 && $session['classification'] === 'MEDIUM' && (int) $session['request_count'] === 3, 'Three rejections accumulate deterministically to score 36/MEDIUM');
    $contributors = $database->query("SELECT rule_code,risk_delta FROM security_score_contributors WHERE security_session_id={$sessionId}")->fetchAll();
    $check(count($contributors) === 3 && array_reduce($contributors, static fn (bool $ok, array $row): bool => $ok && $row['rule_code'] === 'CSRF_REJECTED' && (int) $row['risk_delta'] === 12, true), 'Exactly one +12 contributor exists per rejection');
    SecuritySessionService::correlate((int) $eventIds[0]);
    $check((int) $database->query("SELECT COUNT(*) FROM security_score_contributors WHERE security_session_id={$sessionId}")->fetchColumn() === 3, 'Reprocessing one event is idempotent and creates no duplicate contributor');

    $persisted = (string) $database->query("SELECT GROUP_CONCAT(COALESCE(metadata_json,'')) FROM security_events WHERE id IN ({$ids})")->fetchColumn();
    $labels = (string) $database->query("SELECT GROUP_CONCAT(label) FROM security_score_contributors WHERE security_session_id={$sessionId}")->fetchColumn();
    $check(!str_contains($persisted . $labels, $sentinel), 'Submitted invalid token sentinel is absent from event metadata and contributor evidence');
    $check(!preg_match('/source_ip|csrf_token|cookie|authorization|credential|password|session_identifier/i', $persisted), 'Rejection metadata excludes prohibited secret and source fields');

    $filters = SecurityAnalyticsService::filters([]);
    $eventExport = EvidenceExportService::generate('security_events', 'json', $filters);
    $sessionExport = EvidenceExportService::generate('session_evidence', 'json', $filters, $sessionId);
    $presentation = ($eventExport['body'] ?? '') . ($sessionExport['body'] ?? '');
    $check(!str_contains($presentation, $sentinel), 'Analytics and evidence exports do not expose the invalid-token sentinel');
    $check(!preg_match('/source_ip|source_safe_identifier|source_identifier|source_hash|password_hash|token_hash|authorization_header|session_identifier/i', $presentation), 'Analytics/evidence output preserves H13-H16 data minimization');
} finally {
    $database->exec("DELETE FROM security_score_contributors WHERE id>{$starts['security_score_contributors']}");
    $database->exec("DELETE FROM security_events WHERE id>{$starts['security_events']}");
    $database->exec("DELETE FROM security_sessions WHERE id>{$starts['security_sessions']}");
    $database->exec("DELETE FROM vulnerability_state_changes WHERE id>{$starts['vulnerability_state_changes']}");
    $database->exec("DELETE FROM documents WHERE id>{$starts['documents']}");
    $database->exec("DELETE FROM user_activity WHERE id>{$starts['user_activity']}");
    $database->exec("DELETE FROM users WHERE id>{$starts['users']}");
}

$residual = 0;
foreach ($tables as $table) {
    $residual += (int) $database->query("SELECT COUNT(*) FROM {$table} WHERE id>{$starts[$table]}")->fetchColumn();
}
$check($residual === 0, 'H17 integration removes all exact database fixtures');
echo 'Cleanup: ' . ($residual === 0 ? 'PASS' : 'FAIL') . PHP_EOL;
echo PHP_EOL . "{$passed} H17 integration CSRF checks passed, {$failed} failed, 0 skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
