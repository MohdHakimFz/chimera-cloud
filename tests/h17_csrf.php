<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Security\Csrf;
use App\Security\SecurityEventTaxonomy;
use App\Services\SecurityEventService;
use App\Services\ThreatScoringService;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$source = static fn (string $path): string => (string) file_get_contents($root . '/' . $path);

$routes = $source('routes/web.php');
$middleware = $source('app/Middleware/VerifyCsrf.php');
$csrf = $source('app/Security/Csrf.php');
$response = $source('app/Core/Response.php');
$headers = $source('app/Security/SecurityHeaders.php');
$telemetry = $source('app/Services/SecurityEventService.php');
$labEnvironment = $source('.env.example');

preg_match_all('/\$router->post\(([^\n]+)\);/', $routes, $postMatches);
$postLines = $postMatches[0] ?? [];
$expected = [
    '/login' => '[GuestOnly::class, VerifyCsrf::class]',
    '/register' => '[GuestOnly::class, VerifyCsrf::class]',
    '/logout' => '[Authenticate::class, VerifyCsrf::class]',
    '/profile' => '[Authenticate::class, VerifyCsrf::class]',
    '/documents' => '[Authenticate::class, VerifyCsrf::class]',
    '/documents/{id}/delete' => '[Authenticate::class, VerifyCsrf::class]',
    '/security/lab/modules/{id}/state' => "[new RequireRole(['security_admin']), VerifyCsrf::class]",
];

$check(count($postLines) === 7, 'Exactly seven business-state-changing POST routes are registered');
foreach ($expected as $path => $pipeline) {
    $matching = array_values(array_filter($postLines, static fn (string $line): bool => str_contains($line, "'{$path}'")));
    $check(count($matching) === 1 && str_contains($matching[0], $pipeline), "{$path} has the exact authentication/RBAC-before-CSRF pipeline");
}
$check(array_reduce($postLines, static fn (bool $valid, string $line): bool => $valid && str_contains($line, 'VerifyCsrf::class'), true), 'Every POST route has server-side VerifyCsrf enforcement');
$check(!preg_match('/\$router->(?:put|patch|delete)\s*\(/i', $routes), 'No unreviewed PUT, PATCH, or DELETE mutation route exists');

$forms = [
    'resources/views/auth/login.php',
    'resources/views/auth/register.php',
    'resources/views/layouts/app.php',
    'resources/views/profile/show.php',
    'resources/views/documents/index.php',
    'resources/views/documents/show.php',
    'resources/views/security/lab.php',
];
foreach ($forms as $form) {
    $check(str_contains($source($form), 'csrf_field()'), "{$form} renders the shared CSRF field");
}

$token = Csrf::token();
$check(strlen($token) === 64 && preg_match('/\A[a-f0-9]{64}\z/', $token) === 1, 'Generated CSRF token is 64 hexadecimal characters');
$check(str_contains($csrf, 'random_bytes(32)') && str_contains($csrf, 'bin2hex('), 'Token generation uses 32 cryptographically secure random bytes');
$check(str_contains($csrf, 'hash_equals(') && Csrf::valid($token), 'Valid session token is accepted through constant-time comparison');
$check(!Csrf::valid(null) && !Csrf::valid('') && !Csrf::valid('malformed') && !Csrf::valid(str_repeat('0', 64)), 'Missing, malformed, and incorrect string tokens are rejected');

$check(str_contains($middleware, "\$submittedToken = \$request->input('_token')") && str_contains($middleware, '!is_string($submittedToken)'), 'Middleware requires a string before validation');
$check(!str_contains($middleware, "(string) \$request->input('_token'") && str_contains($middleware, 'Csrf::valid($submittedToken)'), 'Middleware does not cast malformed token values to strings');
$check(str_contains($middleware, "SecurityEventService::record(\$request, 'CSRF_REJECTED'") && str_contains($middleware, 'Response::abort(419'), 'Rejected CSRF records telemetry and returns HTTP 419');
$check(strpos($middleware, 'Response::abort(419') < strpos($middleware, '$next($request)'), 'Rejection terminates before controller/business execution');
$check(!preg_match('/\b(?:INSERT|UPDATE|DELETE|REPLACE|ALTER|DROP|TRUNCATE)\b/i', $middleware), 'CSRF middleware contains no protected business-data mutation');

$definition = SecurityEventTaxonomy::definition('CSRF_REJECTED');
$check($definition['category'] === 'REQUEST_SECURITY' && $definition['severity'] === 'MEDIUM' && $definition['outcome'] === 'REJECTED', 'CSRF_REJECTED taxonomy remains REQUEST_SECURITY/MEDIUM/REJECTED');
$check(ThreatScoringService::weight('CSRF_REJECTED') === 12, 'CSRF_REJECTED scoring weight remains exactly 12');
$check(str_contains($telemetry, "'token'") && str_contains($telemetry, "'csrf'") && !str_contains($middleware, "input('password'"), 'Telemetry rejects token/CSRF metadata and middleware does not inspect credentials');
$safe = SecurityEventService::safeMetadata(['csrf_token' => 'sentinel', 'token' => 'sentinel', 'cookie' => 'sentinel', 'authorization_header' => 'sentinel', 'reason' => 'safe']);
$check($safe === ['reason' => 'safe'], 'Sensitive CSRF, token, cookie, and authorization metadata keys are removed');
$check(str_contains($response, "is_file(BASE_PATH . \"/resources/views/errors/{\$status}.php\")") && str_contains($headers, "'Cache-Control'=>'no-store"), 'HTTP 419 uses a dedicated view under global no-store security headers');
$check(str_contains($labEnvironment, 'VULNERABILITY_LAB_ENABLED=false'), 'Vulnerability LAB remains disabled by default');

echo PHP_EOL . "{$passed} H17 static CSRF checks passed, {$failed} failed, 0 skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
