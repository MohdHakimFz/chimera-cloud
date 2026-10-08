<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/app/Core/Env.php';
App\Core\Env::load($root . '/.env');
if ((string) getenv('TEST_DB_DATABASE') !== 'chimera_test') {
    echo "[FAIL] TEST_DB_DATABASE must be exactly chimera_test.\n";
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
use App\Models\AdaptiveDeception;
use App\Services\AdaptiveDeceptionService;
use App\Services\SecurityEventService;

$database = Database::connection();
$connection = $database->query('SELECT DATABASE() database_name, @@port server_port, CURRENT_USER() authenticated_user')->fetch();
if ($connection['database_name'] !== 'chimera_test' || (int) $connection['server_port'] !== 3308 || !str_starts_with($connection['authenticated_user'], 'chimera_test_app@')) {
    echo "[FAIL] Unsafe Phase 6 integration target.\n";
    exit(1);
}

$eventStart = (int) $database->query('SELECT COALESCE(MAX(id),0) FROM security_events')->fetchColumn();
$sessionStart = (int) $database->query('SELECT COALESCE(MAX(id),0) FROM security_sessions')->fetchColumn();
$usersBefore = (int) $database->query('SELECT COUNT(*) FROM users')->fetchColumn();
$documentsBefore = (int) $database->query('SELECT COUNT(*) FROM documents')->fetchColumn();
$tokenIds = [];
$passes = 0;
$failures = 0;
$check = static function (bool $condition, string $label) use (&$passes, &$failures): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . "\n";
    $condition ? $passes++ : $failures++;
};
$request = new Request('GET', '/adaptive-test', [], [], ['REMOTE_ADDR' => '192.0.2.60', 'HTTP_USER_AGENT' => 'CHIMERA Phase6 Test'], []);
$decoy = ['decoy_identifier' => 'DEC-PHASE6', 'response_mode' => 'SYNTHETIC_JSON'];

try {
    $insertToken = $database->prepare('INSERT INTO honeytokens (token_identifier, description, token_hash, is_active, risk_weight) VALUES (?, ?, ?, 1, 0)');
    foreach ([['HT-API-001', 'Phase 6 synthetic API marker.', 'CHM_HONEY_HT_API_001'], ['HT-BACKUP-001', 'Phase 6 synthetic backup marker.', 'CHM_HONEY_HT_BACKUP_001']] as $token) {
        $insertToken->execute([$token[0], $token[1], hash('sha256', $token[2])]);
        $tokenIds[] = (int) $database->lastInsertId();
    }

    $fallback = AdaptiveDeceptionService::select($request, null);
    $check($fallback['profile']['name'] === 'LOW' && $fallback['fallback'] === true && $fallback['security_session_id'] === null, 'No security session selects the safe LOW fallback');

    for ($index = 0; $index < 4; $index++) {
        SecurityEventService::record($request, 'LOGIN_FAILURE');
    }
    $medium = AdaptiveDeceptionService::select($request, null);
    $check($medium['score'] === 20 && $medium['threat_level'] === 'MEDIUM' && $medium['profile']['name'] === 'MEDIUM', 'Active assessment selects MEDIUM at score 20');
    $scoreBeforeDecision = $medium['score'];
    AdaptiveDeceptionService::recordDecision($request, null, $decoy, $medium);
    $sessionId = (int) $medium['security_session_id'];
    $scoreAfterDecision = (int) $database->query("SELECT threat_score FROM security_sessions WHERE id={$sessionId}")->fetchColumn();
    $check($scoreAfterDecision === $scoreBeforeDecision, 'Profile-selection and render telemetry do not increase score');

    $firstDecoy = SecurityEventService::record($request, 'DECOY_ACCESSED', null, ['target_type' => 'decoy', 'target_identifier' => 'DEC-PHASE6', 'metadata' => ['decoy_identifier' => 'DEC-PHASE6', 'deception_profile' => 'MEDIUM']]);
    $secondDecoy = SecurityEventService::record($request, 'DECOY_ACCESSED', null, ['target_type' => 'decoy', 'target_identifier' => 'DEC-PHASE6', 'metadata' => ['decoy_identifier' => 'DEC-PHASE6', 'deception_profile' => 'MEDIUM']]);
    $deltas = $database->query("SELECT id,risk_delta FROM security_events WHERE id IN ({$firstDecoy},{$secondDecoy}) ORDER BY id")->fetchAll();
    $scoreAfterRefresh = (int) $database->query("SELECT threat_score FROM security_sessions WHERE id={$sessionId}")->fetchColumn();
    $check((int) $deltas[0]['risk_delta'] === 20 && (int) $deltas[1]['risk_delta'] === 0 && $scoreAfterRefresh === 40, 'Same-decoy refresh is recorded but contributes only once per security session');

    SecurityEventService::record($request, 'LOGIN_FAILURE');
    $high = AdaptiveDeceptionService::select($request, null);
    $check($high['score'] === 45 && $high['profile']['name'] === 'HIGH', 'Meaningful additional behavior selects HIGH at score 45');
    $highTokens = AdaptiveDeceptionService::exposedHoneytokens($high['profile']);
    $check($highTokens === ['CHM_HONEY_HT_API_001'], 'HIGH exposes exactly one active registered synthetic marker');
    AdaptiveDeceptionService::recordDecision($request, null, $decoy, $high);

    SecurityEventService::record($request, 'HONEYTOKEN_TRIGGERED', null, ['target_type' => 'honeytoken', 'target_identifier' => 'HT-API-001', 'metadata' => ['honeytoken_identifier' => 'HT-API-001', 'deception_profile' => 'HIGH']]);
    $critical = AdaptiveDeceptionService::select($request, null);
    $check($critical['score'] === 80 && $critical['profile']['name'] === 'CRITICAL', 'Controlled honeytoken interaction advances assessment to CRITICAL');
    $criticalTokens = AdaptiveDeceptionService::exposedHoneytokens($critical['profile']);
    $check($criticalTokens === ['CHM_HONEY_HT_API_001', 'CHM_HONEY_HT_BACKUP_001'], 'CRITICAL exposes only the two active registered synthetic markers');
    AdaptiveDeceptionService::recordDecision($request, null, $decoy, $critical);

    $adaptiveDelta = (int) $database->query("SELECT COALESCE(SUM(risk_delta),0) FROM security_events WHERE id>{$eventStart} AND event_type IN ('DECEPTION_PROFILE_SELECTED','DECEPTION_PROFILE_CHANGED','ADAPTIVE_DECOY_RENDERED')")->fetchColumn();
    $adaptiveContributors = (int) $database->query("SELECT COUNT(*) FROM security_score_contributors WHERE security_session_id={$sessionId} AND rule_code IN ('DECEPTION_PROFILE_SELECTED','DECEPTION_PROFILE_CHANGED','ADAPTIVE_DECOY_RENDERED')")->fetchColumn();
    $check($adaptiveDelta === 0 && $adaptiveContributors === 0, 'Adaptation telemetry has zero delta and creates no score contributor');

    $explanation = AdaptiveDeception::forSession($sessionId);
    $eventTypes = array_column($explanation['events'], 'event_type');
    $check($explanation['current_profile'] === 'CRITICAL' && in_array('DECEPTION_PROFILE_CHANGED', $eventTypes, true) && in_array('ADAPTIVE_DECOY_RENDERED', $eventTypes, true), 'Session explanation reconstructs profile transitions and renders');

    $database->exec("UPDATE security_sessions SET threat_score=20,classification='MEDIUM' WHERE id={$sessionId}");
    $stable = AdaptiveDeceptionService::select($request, null);
    $check($stable['profile']['name'] === 'CRITICAL', 'Profile does not downgrade within the same active security session');

    $metadataPayload = (string) $database->query("SELECT GROUP_CONCAT(metadata_json SEPARATOR '\n') FROM security_events WHERE id>{$eventStart}")->fetchColumn();
    $check(!str_contains($metadataPayload, 'CHM_HONEY_') && !preg_match('/password|cookie|authorization|session_identifier|DB_PASSWORD/i', $metadataPayload), 'Adaptation metadata excludes marker material and authentication secrets');
    $check((int) $database->query('SELECT COUNT(*) FROM users')->fetchColumn() === $usersBefore && (int) $database->query('SELECT COUNT(*) FROM documents')->fetchColumn() === $documentsBefore, 'Adaptive assessment does not modify users or documents');

    echo "\n{$passes} Phase 6 integration checks passed, {$failures} failed.\n";
} finally {
    $database->exec("DELETE FROM security_events WHERE id>{$eventStart}");
    $database->exec("DELETE FROM security_sessions WHERE id>{$sessionStart}");
    if ($tokenIds !== []) {
        $placeholders = implode(',', array_fill(0, count($tokenIds), '?'));
        $delete = $database->prepare("DELETE FROM honeytokens WHERE id IN ({$placeholders})");
        $delete->execute($tokenIds);
    }
}

exit($failures === 0 ? 0 : 1);
