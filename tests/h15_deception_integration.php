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
use App\Models\AdaptiveDeception;
use App\Models\Honeytoken;
use App\Services\AdaptiveDeceptionService;
use App\Services\HoneytokenService;
use App\Services\SecurityEventService;

$database = Database::connection();
$connection = $database->query('SELECT DATABASE() database_name, @@port server_port, CURRENT_USER() authenticated_user')->fetch();
if ($connection['database_name'] !== 'chimera_test' || (int) $connection['server_port'] !== 3308 || !str_starts_with($connection['authenticated_user'], 'chimera_test_app@')) {
    echo "[FAIL] Unsafe H15 integration target." . PHP_EOL;
    exit(1);
}

$starts = [];
foreach (['security_events', 'security_sessions', 'honeytokens'] as $table) {
    $starts[$table] = (int) $database->query("SELECT COALESCE(MAX(id),0) FROM {$table}")->fetchColumn();
}
$usersBefore = (int) $database->query('SELECT COUNT(*) FROM users')->fetchColumn();
$documentsBefore = (int) $database->query('SELECT COUNT(*) FROM documents')->fetchColumn();
$labStatesBefore = (string) $database->query("SELECT COALESCE(GROUP_CONCAT(CONCAT(id, ':', state) ORDER BY id SEPARATOR ','), '') FROM vulnerability_modules")->fetchColumn();

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};

$peer = implode('.', [192, 0, 2, 215]);
$request = new Request('GET', '/h15/synthetic', [], [], [
    'REMOTE_ADDR' => $peer,
    'HTTP_USER_AGENT' => 'CHIMERA H15 Local Test',
], []);
$tokenIdentifier = 'HT-H15-' . strtoupper(bin2hex(random_bytes(4)));
$tokenMaterial = HoneytokenService::material($tokenIdentifier);

try {
    $insertSession = $database->prepare("INSERT INTO security_sessions (session_identifier, user_id, source_hash, user_agent_hash, threat_score, classification, request_count) VALUES (:identifier, NULL, :source_hash, NULL, 45, 'HIGH', 2)");
    $insertSession->execute([
        'identifier' => 'h15-' . bin2hex(random_bytes(16)),
        'source_hash' => hash('sha256', 'h15-legacy-source-fixture'),
    ]);
    $legacySessionId = (int) $database->lastInsertId();

    $legacyMetadata = json_encode([
        'category' => 'DECEPTION',
        'outcome' => 'SUCCESS',
        'selected_profile' => 'HIGH',
        'selection_reason' => 'legacy_fixture',
        'response_variant' => 'investigative',
        'source_ip' => 'legacy-sensitive-source',
        'source_safe_identifier' => 'legacy-sensitive-correlation',
    ], JSON_THROW_ON_ERROR);
    $insertLegacy = $database->prepare("INSERT INTO security_events (security_session_id, event_type, source_safe_identifier, endpoint, http_method, user_agent_summary, severity, risk_delta, description, metadata_json) VALUES (:session_id, 'ADAPTIVE_DECOY_RENDERED', :safe_source, '/h15/legacy-adaptive', 'GET', 'CHIMERA H15 Local Test', 'INFO', 0, 'A configured decoy rendered a safe adaptive profile.', :metadata)");
    $insertLegacy->execute([
        'session_id' => $legacySessionId,
        'safe_source' => hash('sha256', 'h15-safe-correlation-fixture'),
        'metadata' => $legacyMetadata,
    ]);

    $recent = AdaptiveDeception::recentEvents(100);
    $recentJson = json_encode(['data' => $recent], JSON_THROW_ON_ERROR);
    $check(!str_contains($recentJson, 'source_ip'), 'Adaptive events API model payload strips legacy source_ip');
    $check(!str_contains($recentJson, 'source_safe_identifier'), 'Adaptive events API model payload strips safe-source identifiers');

    $session = AdaptiveDeception::forSession($legacySessionId);
    $sessionJson = json_encode(['data' => $session], JSON_THROW_ON_ERROR);
    $check(!str_contains($sessionJson, 'source_ip'), 'Adaptive session API model payload strips legacy source_ip');
    $check(!str_contains($sessionJson, 'source_safe_identifier'), 'Adaptive session API model payload strips safe-source identifiers');
    $check(($session['events'][0]['metadata']['selected_profile'] ?? null) === 'HIGH' && ($session['events'][0]['metadata']['response_variant'] ?? null) === 'investigative', 'Adaptive session payload retains required safe profile metadata');

    $insertToken = $database->prepare('INSERT INTO honeytokens (token_identifier, description, token_hash, is_active, risk_weight) VALUES (:identifier, :description, :token_hash, 1, 0)');
    $insertToken->execute([
        'identifier' => $tokenIdentifier,
        'description' => 'H15 local synthetic marker.',
        'token_hash' => hash('sha256', $tokenMaterial),
    ]);

    $triggered = HoneytokenService::trigger($request, $tokenMaterial);
    $honeyEvent = $database->query("SELECT id, security_session_id, risk_delta FROM security_events WHERE id > {$starts['security_events']} AND event_type = 'HONEYTOKEN_TRIGGERED' ORDER BY id DESC LIMIT 1")->fetch();
    $honeyLinkCount = is_array($honeyEvent)
        ? (int) $database->query('SELECT COUNT(*) FROM honeytoken_events WHERE security_event_id = ' . (int) $honeyEvent['id'])->fetchColumn()
        : 0;
    $check($triggered && is_array($honeyEvent) && (int) $honeyEvent['risk_delta'] === 35, 'Valid local honeytoken trigger retains the approved 35-point contribution');
    $check($honeyLinkCount === 1, 'Normal honeytoken flow creates exactly one linked honeytoken event');

    $honeyRecent = Honeytoken::recentEvents(100);
    $matchingHoney = array_values(array_filter($honeyRecent, static fn (array $row): bool => ($row['token_identifier'] ?? null) === $tokenIdentifier));
    $check(count($matchingHoney) === 1 && !array_key_exists('source_safe_identifier', $matchingHoney[0]), 'Honeytoken recent-event presentation omits the safe-source identifier');

    $safeInventory = Honeytoken::allSafe();
    $matchingInventory = array_values(array_filter($safeInventory, static fn (array $row): bool => ($row['token_identifier'] ?? null) === $tokenIdentifier));
    $inventoryJson = json_encode(['data' => $matchingInventory], JSON_THROW_ON_ERROR);
    $check(count($matchingInventory) === 1 && !preg_match('/token_hash|source_ip|source_safe_identifier|credential|session_identifier/i', $inventoryJson), 'Honeytoken inventory API model payload remains minimized');
    $check(!str_contains($inventoryJson, $tokenMaterial), 'Honeytoken inventory does not expose synthetic marker material');

    $firstDecoyId = SecurityEventService::record($request, 'DECOY_ACCESSED', null, [
        'target_type' => 'decoy',
        'target_identifier' => 'DEC-H15-REPEAT',
        'metadata' => ['decoy_identifier' => 'DEC-H15-REPEAT', 'deception_profile' => 'HIGH'],
    ]);
    $secondDecoyId = SecurityEventService::record($request, 'DECOY_ACCESSED', null, [
        'target_type' => 'decoy',
        'target_identifier' => 'DEC-H15-REPEAT',
        'metadata' => ['decoy_identifier' => 'DEC-H15-REPEAT', 'deception_profile' => 'HIGH'],
    ]);
    $decoyRows = $database->query('SELECT risk_delta FROM security_events WHERE id IN (' . (int) $firstDecoyId . ',' . (int) $secondDecoyId . ') ORDER BY id')->fetchAll();
    $check(count($decoyRows) === 2 && (int) $decoyRows[0]['risk_delta'] === 20 && (int) $decoyRows[1]['risk_delta'] === 0, 'Same-decoy scoring remains 20 for the first access and zero for the repeat');

    $adaptive = AdaptiveDeceptionService::select($request, null);
    $scoreBeforeDecision = $adaptive['score'];
    AdaptiveDeceptionService::recordDecision($request, null, ['decoy_identifier' => 'DEC-H15-REPEAT'], $adaptive);
    $activeSessionId = (int) $adaptive['security_session_id'];
    $scoreAfterDecision = (int) $database->query("SELECT threat_score FROM security_sessions WHERE id = {$activeSessionId}")->fetchColumn();
    $adaptivePositive = (int) $database->query("SELECT COUNT(*) FROM security_events WHERE id > {$starts['security_events']} AND event_type IN ('DECEPTION_PROFILE_SELECTED','DECEPTION_PROFILE_CHANGED','ADAPTIVE_DECOY_RENDERED') AND risk_delta <> 0")->fetchColumn();
    $check($scoreAfterDecision === $scoreBeforeDecision && $adaptivePositive === 0, 'Adaptive selection and rendering remain zero-weight');

    $check((int) $database->query('SELECT COUNT(*) FROM users')->fetchColumn() === $usersBefore, 'H15 integration does not mutate users or roles');
    $check((int) $database->query('SELECT COUNT(*) FROM documents')->fetchColumn() === $documentsBefore, 'H15 integration does not mutate documents');
    $check((string) $database->query("SELECT COALESCE(GROUP_CONCAT(CONCAT(id, ':', state) ORDER BY id SEPARATOR ','), '') FROM vulnerability_modules")->fetchColumn() === $labStatesBefore, 'H15 integration does not mutate vulnerability-lab state');

} finally {
    $database->exec("DELETE FROM security_events WHERE id > {$starts['security_events']}");
    $database->exec("DELETE FROM security_sessions WHERE id > {$starts['security_sessions']}");
    $database->exec("DELETE FROM honeytokens WHERE id > {$starts['honeytokens']}");
}

$residual = (int) $database->query(
    "SELECT
       (SELECT COUNT(*) FROM security_events WHERE id > {$starts['security_events']}) +
       (SELECT COUNT(*) FROM security_sessions WHERE id > {$starts['security_sessions']}) +
       (SELECT COUNT(*) FROM honeytokens WHERE id > {$starts['honeytokens']})"
)->fetchColumn();
$check($residual === 0, 'H15 integration removes all exact test fixtures');

echo "Cleanup: " . ($residual === 0 ? 'PASS' : 'FAIL') . PHP_EOL;
echo PHP_EOL . "{$passed} H15 integration/privacy checks passed, {$failed} failed." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
