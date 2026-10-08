<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Models\AdaptiveDeception;
use App\Security\SecurityEventTaxonomy;
use App\Services\AdaptiveDeceptionService;
use App\Services\ThreatScoringService;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$source = static fn (string $path): string => (string) file_get_contents($root . '/' . $path);

$adaptiveModel = $source('app/Models/AdaptiveDeception.php');
$honeytokenModel = $source('app/Models/Honeytoken.php');
$deceptionModel = $source('app/Models/Deception.php');
$adaptiveApi = $source('app/Controllers/AdaptiveDeceptionApiController.php');
$deceptionApi = $source('app/Controllers/DeceptionApiController.php');
$routes = $source('routes/web.php');
$labEnvironment = $source('.env.example');

$present = new ReflectionMethod(AdaptiveDeception::class, 'present');
$legacy = $present->invoke(null, [
    'id' => '15',
    'security_session_id' => '9',
    'event_type' => 'ADAPTIVE_DECOY_RENDERED',
    'endpoint' => '/synthetic-h15',
    'http_method' => 'GET',
    'severity' => 'INFO',
    'risk_delta' => '0',
    'metadata_json' => json_encode([
        'selected_profile' => 'HIGH',
        'selection_reason' => 'legacy_fixture',
        'source_ip' => 'legacy-sensitive-source',
        'source_safe_identifier' => 'legacy-sensitive-correlation',
    ], JSON_THROW_ON_ERROR),
    'source_ip' => 'legacy-sensitive-source',
    'source_safe_identifier' => 'legacy-sensitive-correlation',
    'created_at' => '2026-10-06 00:00:00',
]);

$check(!isset($legacy['metadata']['source_ip'], $legacy['source_ip']), 'Adaptive presenter strips legacy raw-source fields');
$check(!isset($legacy['metadata']['source_safe_identifier'], $legacy['source_safe_identifier']), 'Adaptive presenter strips replacement safe-source fields');
$check(($legacy['metadata']['selected_profile'] ?? null) === 'HIGH' && ($legacy['metadata']['selection_reason'] ?? null) === 'legacy_fixture', 'Adaptive presenter preserves legitimate safe decision metadata');
$check(str_contains($adaptiveModel, "\$event['metadata']['source_ip']") && str_contains($adaptiveModel, "\$event['metadata']['source_safe_identifier']"), 'Common adaptive model boundary contains explicit legacy-source sanitization');
$check(!preg_match('/SELECT[^;]+source_safe_identifier[^;]+FROM honeytoken_events/is', $honeytokenModel), 'Honeytoken recent-event query does not select a safe-source identifier');
$check(str_contains($adaptiveApi, 'AdaptiveDeception::recentEvents(100)') && str_contains($adaptiveApi, 'AdaptiveDeception::forSession('), 'Both adaptive API serializers use the common sanitized model boundary');
$check(!preg_match('/source_ip|source_safe_identifier/i', $deceptionApi), 'Deception API controller introduces no source identifier fields');
$check(str_contains($deceptionModel, "unset(\$row['metadata']['source_ip']"), 'Primary deception event presentation retains H13 legacy sanitization');

$profiles = AdaptiveDeceptionService::policy();
$check(array_keys($profiles) === ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 'Adaptive policy still defines exactly LOW, MEDIUM, HIGH, and CRITICAL');
$check($profiles['LOW']['metadata_richness'] === 1 && count($profiles['LOW']['breadcrumbs']) === 0 && count($profiles['LOW']['honeytoken_identifiers']) === 0, 'LOW profile remains minimal');
$check($profiles['MEDIUM']['metadata_richness'] === 2 && count($profiles['MEDIUM']['breadcrumbs']) === 2 && count($profiles['MEDIUM']['honeytoken_identifiers']) === 0, 'MEDIUM profile remains contextual without markers');
$check($profiles['HIGH']['metadata_richness'] === 3 && count($profiles['HIGH']['breadcrumbs']) === 3 && count($profiles['HIGH']['honeytoken_identifiers']) === 1, 'HIGH profile remains investigative with one controlled marker');
$check($profiles['CRITICAL']['metadata_richness'] === 4 && count($profiles['CRITICAL']['breadcrumbs']) === 4 && count($profiles['CRITICAL']['honeytoken_identifiers']) === 2, 'CRITICAL profile remains immersive-safe with two controlled markers');
$check(AdaptiveDeceptionService::profileForLevel('UNAVAILABLE')['name'] === 'LOW', 'Unavailable assessment still selects the safe LOW fallback');

$check(ThreatScoringService::weight('DECOY_ACCESSED') === 20, 'Decoy score remains 20');
$check(ThreatScoringService::weight('HONEYTOKEN_TRIGGERED') === 35, 'Honeytoken score remains 35');
foreach (['DECEPTION_PROFILE_SELECTED', 'DECEPTION_PROFILE_CHANGED', 'ADAPTIVE_DECOY_RENDERED'] as $eventType) {
    $check(SecurityEventTaxonomy::definition($eventType)['category'] === 'DECEPTION' && ThreatScoringService::weight($eventType) === 0, "{$eventType} remains zero-weight deception telemetry");
}

foreach (['/security/deception', '/security/adaptive', '/api/security/deception/summary', '/api/security/decoys', '/api/security/honeytokens', '/api/security/deception/events', '/api/security/adaptive/summary', '/api/security/sessions/{id}/deception', '/api/security/adaptive/events'] as $path) {
    $check(preg_match('#' . preg_quote($path, '#') . "'.*new RequireRole\(\['security_admin'\]\)#", $routes) === 1, "{$path} remains Security Admin-only");
}

$deceptionScope = $source('app/Services/DecoyService.php')
    . $source('app/Services/HoneytokenService.php')
    . $source('app/Services/AdaptiveDeceptionService.php')
    . $source('app/Controllers/DecoyController.php');
$check(!preg_match('/\b(shell_exec|system|exec|passthru|proc_open|popen|eval)\s*\(|file_put_contents|unlink\s*\(|curl_|fsockopen|stream_socket_client/i', $deceptionScope), 'Deception scope contains no command, file-write, or external-network primitive');
$check(!preg_match('/\b(?:INSERT|UPDATE|DELETE)\s+(?:INTO\s+|FROM\s+)?(?:users|documents)\b/i', $deceptionScope), 'Deception scope cannot mutate users or documents');
$check(str_contains($labEnvironment, 'VULNERABILITY_LAB_ENABLED=false'), 'Vulnerability lab remains disabled by default');

echo PHP_EOL . "{$passed} H15 static/privacy checks passed, {$failed} failed." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
