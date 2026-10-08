<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Security\SecurityEventTaxonomy;
use App\Services\SecurityEventService;
use App\Core\Request;

$passes = 0;
$failures = 0;
$check = static function (bool $condition, string $label) use (&$passes, &$failures): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . "\n";
    $condition ? $passes++ : $failures++;
};
$source = static fn (string $path): string => (string) file_get_contents($root . '/' . $path);

$expected = ['LOGIN_SUCCESS','LOGIN_FAILURE','LOGOUT','REGISTRATION_SUCCESS','ACCESS_DENIED','ROLE_ACCESS_DENIED','OWNERSHIP_ACCESS_DENIED','CSRF_REJECTED','INVALID_REQUEST','DOCUMENT_UPLOAD_SUCCESS','DOCUMENT_UPLOAD_REJECTED','DOCUMENT_DOWNLOAD','DOCUMENT_DELETE','DOCUMENT_INTEGRITY_FAILURE','PROFILE_UPDATED','SECURITY_RELEVANT_APPLICATION_ERROR'];
$check(array_diff($expected, SecurityEventTaxonomy::eventTypes()) === [], 'Taxonomy defines all required Phase 3 event types');
$check(SecurityEventTaxonomy::definition('LOGIN_FAILURE')['severity'] === 'MEDIUM', 'Login failure severity is deterministic');
$check(SecurityEventTaxonomy::definition('DOCUMENT_INTEGRITY_FAILURE')['severity'] === 'HIGH', 'Integrity failure severity is deterministic');
$check(SecurityEventTaxonomy::definition('LOGIN_SUCCESS')['severity'] === 'INFO', 'Successful authentication severity is informational');
$check(SecurityEventTaxonomy::severities() === ['INFO','LOW','MEDIUM','HIGH','CRITICAL'], 'Severity vocabulary is constrained');

$safe = SecurityEventService::safeMetadata([
    'reason' => 'safe', 'attempt' => 2, 'password' => 'never', 'csrf_token' => 'never',
    'session_cookie' => 'never', 'authorization_header' => 'never', 'filesystem_path' => 'never',
    'document_content' => 'never', 'nested' => [['unsafe']],
]);
$check(($safe['reason'] ?? null) === 'safe' && ($safe['attempt'] ?? null) === 2, 'Telemetry metadata retains allowlisted scalar context');
$check(!isset($safe['password'], $safe['csrf_token'], $safe['session_cookie'], $safe['authorization_header'], $safe['filesystem_path'], $safe['document_content']), 'Telemetry metadata drops sensitive keys');
$check(!isset($safe['nested']), 'Telemetry metadata drops non-scalar nested structures');

$service = $source('app/Services/SecurityEventService.php');
$routes = $source('routes/web.php');
$model = $source('app/Models/SecurityEvent.php');
$controller = $source('app/Controllers/SecurityController.php') . $source('app/Controllers/SecurityApiController.php');
$overview = $source('resources/views/security/index.php');
$detail = $source('resources/views/security/show.php');
$deceptionModel = $source('app/Models/Deception.php');
$deceptionView = $source('resources/views/security/deception.php');
$check(str_contains($service, "'REMOTE_ADDR'"), 'Source attribution uses the direct peer address');
$check(!str_contains($service, 'X-Forwarded-For') && !str_contains($service, 'HTTP_FORWARDED'), 'Untrusted proxy headers are not used');
$check(!str_contains($service, "'source_ip' =>"), 'Raw source address is not persisted in telemetry metadata');
$check(!str_contains($model, "JSON_EXTRACT(metadata_json, '$.source_ip')") && !str_contains($controller, "'source_ip'"), 'Telemetry model and controllers do not support raw source-address filtering');
$check(!str_contains($overview . $detail, 'Source IP') && !str_contains($overview, 'name="source_ip"'), 'Telemetry views do not render or filter raw source addresses');
$check(!str_contains($deceptionView, 'Source identifier') && !str_contains($deceptionView, 'source_safe_identifier'), 'Deception view does not expose a source identifier replacement');
$check(!str_contains($deceptionModel, 'SELECT id, event_type, source_safe_identifier') && str_contains($deceptionModel, "unset(\$row['metadata']['source_ip']"), 'Deception presentation strips legacy raw source metadata');
$check(str_contains($overview, 'deterministic threat scoring') && str_contains($overview, 'No automated blocking or account action'), 'Telemetry overview accurately distinguishes scoring from automated response');

$envProbe = 'CHIMERA_ENV_PRIORITY_TEST';
$_ENV[$envProbe] = 'env-array-value';
putenv($envProbe . '=process-value');
$check(env($envProbe) === 'env-array-value', 'Environment helper prefers values loaded into $_ENV');
unset($_ENV[$envProbe]);
putenv($envProbe);

$originalTelemetryKeyPresent = array_key_exists('TELEMETRY_HASH_KEY', $_ENV);
$originalTelemetryKey = $_ENV['TELEMETRY_HASH_KEY'] ?? null;
$_ENV['TELEMETRY_HASH_KEY'] = 'phase-3-hmac-determinism-key';
$directPeer = '192.0.2.44';
$requestA = new Request('GET', '/phase3-source-check', [], [], [
    'REMOTE_ADDR' => $directPeer,
    'HTTP_X_FORWARDED_FOR' => '198.51.100.9',
    'HTTP_FORWARDED' => 'for=203.0.113.7',
]);
$requestB = new Request('GET', '/phase3-source-check', [], [], [
    'REMOTE_ADDR' => $directPeer,
    'HTTP_X_FORWARDED_FOR' => '203.0.113.250',
]);
$identifierA = SecurityEventService::safeSourceIdentifier($requestA);
$identifierB = SecurityEventService::safeSourceIdentifier($requestB);
$expectedIdentifier = hash_hmac('sha256', $directPeer, 'phase-3-hmac-determinism-key');
$check($identifierA === $expectedIdentifier && $identifierB === $expectedIdentifier && preg_match('/\A[a-f0-9]{64}\z/', (string) $identifierA) === 1, 'Safe source correlation remains deterministic HMAC-SHA-256 and ignores forwarded headers');
if ($originalTelemetryKeyPresent) {
    $_ENV['TELEMETRY_HASH_KEY'] = $originalTelemetryKey;
} else {
    unset($_ENV['TELEMETRY_HASH_KEY']);
}
$check(str_contains($service, 'risk_delta, description') && str_contains($service, ':severity, 0,'), 'Telemetry writes leave threat-score delta at zero');
$check(str_contains($service, 'catch (Throwable') && str_contains($service, 'return null'), 'Telemetry recording fails open without breaking application flow');
$check(!str_contains($service, '$request->all()'), 'Telemetry never captures complete request bodies');
$check(str_contains($routes, "'/api/security/events'") && str_contains($routes, "'/api/security/summary'"), 'Security telemetry API routes are registered');
$check(substr_count($routes, "new RequireRole(['security_admin'])") >= 5, 'Dashboard, detail, and APIs require exact Security Admin role');
$check(str_contains($model, 'JSON_EXTRACT') && str_contains($model, 'LIMIT :limit'), 'Telemetry queries use normalized metadata and bounded result sets');
$check(!preg_match('/threat_score\s*[+\-=]|risk_delta\s*[+\-]/i', $service . $model), 'Phase 3 contains no threat-scoring calculation');

echo "\n{$passes} Phase 3 static checks passed, {$failures} failed.\n";
exit($failures === 0 ? 0 : 1);
