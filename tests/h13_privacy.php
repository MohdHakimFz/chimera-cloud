<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Core\Request;
use App\Models\SecurityEvent;
use App\Services\SecurityEventService;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$source = static fn (string $path): string => (string) file_get_contents($root . '/' . $path);

$service = $source('app/Services/SecurityEventService.php');
$sessionService = $source('app/Services/SecuritySessionService.php');
$eventModel = $source('app/Models/SecurityEvent.php');
$deceptionModel = $source('app/Models/Deception.php');
$controllers = $source('app/Controllers/SecurityController.php') . $source('app/Controllers/SecurityApiController.php');
$overview = $source('resources/views/security/index.php');
$detail = $source('resources/views/security/show.php');
$deception = $source('resources/views/security/deception.php');
$helpers = $source('app/Helpers/functions.php');

$check(str_contains($service, "'REMOTE_ADDR'") && !str_contains($service, "'source_ip' =>"), 'Direct peer input remains transient and raw source metadata is not persisted');
$check(!str_contains($service, 'X-Forwarded-For') && !str_contains($service, 'HTTP_X_FORWARDED_FOR') && !str_contains($service, 'HTTP_FORWARDED'), 'Proxy-controlled forwarding headers remain ignored');

$hadKey = array_key_exists('TELEMETRY_HASH_KEY', $_ENV);
$oldKey = $_ENV['TELEMETRY_HASH_KEY'] ?? null;
$_ENV['TELEMETRY_HASH_KEY'] = 'h13-local-privacy-test-key';
$peer = '192.0.2.77';
$request = new Request('GET', '/h13-local-check', [], [], [
    'REMOTE_ADDR' => $peer,
    'HTTP_X_FORWARDED_FOR' => '198.51.100.4',
]);
$identifier = SecurityEventService::safeSourceIdentifier($request);
$check($identifier === hash_hmac('sha256', $peer, 'h13-local-privacy-test-key') && preg_match('/\A[a-f0-9]{64}\z/', (string) $identifier) === 1, 'Safe correlation identifier remains deterministic 64-character HMAC-SHA-256');
if ($hadKey) {
    $_ENV['TELEMETRY_HASH_KEY'] = $oldKey;
} else {
    unset($_ENV['TELEMETRY_HASH_KEY']);
}

$check(str_contains($sessionService, 'source_safe_identifier') && str_contains($sessionService, "user_id IS NULL") && str_contains($sessionService, 'user_id = :user_id'), 'Authenticated and anonymous correlation boundaries remain source-safe and distinct');
$check(!preg_match('/ThreatScoringService|WEIGHTS|threshold/i', $service . $eventModel . $controllers . $overview . $detail . $deceptionModel . $deception), 'Privacy remediation does not alter scoring weights or thresholds');

$present = new ReflectionMethod(SecurityEvent::class, 'present');
$legacy = $present->invoke(null, [
    'id' => '7',
    'event_type' => 'ACCESS_DENIED',
    'endpoint' => '/dashboard',
    'http_method' => 'GET',
    'user_agent_summary' => 'Test agent',
    'severity' => 'LOW',
    'description' => 'Access denied.',
    'metadata_json' => json_encode(['category' => 'AUTHORIZATION', 'outcome' => 'DENIED', 'source_ip' => '192.0.2.99'], JSON_THROW_ON_ERROR),
    'actor_user_id' => null,
    'category' => 'AUTHORIZATION',
    'outcome' => 'DENIED',
    'target_type' => null,
    'target_identifier' => null,
    'source_ip' => '192.0.2.99',
    'source_safe_identifier' => str_repeat('a', 64),
    'created_at' => '2026-10-05 00:00:00',
]);
$check(!isset($legacy['metadata']['source_ip'], $legacy['source_ip'], $legacy['source_safe_identifier'], $legacy['metadata_json']), 'Legacy raw and pseudonymous source fields are stripped before model/API presentation');
$check(!str_contains($controllers, "'source_ip'") && !str_contains($eventModel, "JSON_EXTRACT(metadata_json, '$.source_ip')"), 'Telemetry API path has no raw source filter or projection');
$check(str_contains($deceptionModel, "unset(\$row['metadata']['source_ip']") && !str_contains($deceptionModel, 'SELECT id, event_type, source_safe_identifier'), 'Deception API output strips legacy raw source and omits safe identifiers');
$check(!preg_match('/Source IP|name="source_ip"|source_safe_identifier|Source identifier/i', $overview . $detail . $deception), 'Telemetry views expose no raw or replacement source identifier');
$check(str_contains($overview, 'deterministic threat scoring') && str_contains($overview, 'No automated blocking or account action'), 'Telemetry overview states that scoring is active and automated action is inactive');
$check(str_contains($helpers, "array_key_exists(\$key, \$_ENV)") && strpos($helpers, '$_ENV[$key]') < strpos($helpers, 'getenv($key)'), 'InfinityFree environment compatibility prefers $_ENV before getenv()');

$forbidden = SecurityEventService::safeMetadata([
    'source_ip' => '192.0.2.9',
    'password' => 'secret',
    'authorization_header' => 'secret',
    'csrf_token' => 'secret',
    'session_identifier' => 'secret',
    'safe_reason' => 'retained',
]);
$check($forbidden === ['safe_reason' => 'retained'], 'Forbidden metadata protection rejects source, credential, authorization, CSRF, and session keys');

echo PHP_EOL . "{$passed} H13 privacy checks passed, {$failed} failed." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
