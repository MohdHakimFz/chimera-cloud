<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$passes = 0;

function check(bool $condition, string $label): void
{
    global $failures, $passes;
    if ($condition) {
        $passes++;
        echo "[PASS] {$label}\n";
        return;
    }

    $failures[] = $label;
    echo "[FAIL] {$label}\n";
}

function source(string $relative): string
{
    global $root;
    $contents = file_get_contents($root . '/' . $relative);
    return $contents === false ? '' : $contents;
}

$routes = source('routes/web.php');
$auth = source('app/Security/Auth.php');
$user = source('app/Models/User.php');
$schema = source('database/schema.sql');
$headers = source('app/Security/SecurityHeaders.php');

check(PHP_VERSION_ID >= 80100, 'PHP runtime is 8.1 or newer');
check(password_verify('phase-one-check', password_hash('phase-one-check', PASSWORD_DEFAULT)), 'Password hashing and verification work');
check(str_contains($auth, 'Session::regenerate()'), 'Authentication regenerates the session ID');
check(str_contains($auth, 'password_verify('), 'Authentication verifies password hashes');
check(str_contains($user, "'role' => 'user'"), 'Public registration assigns the User role in application code');
check(!str_contains($user, "'role' => \$"), 'Registration does not take a role variable from request data');
check(str_contains($routes, "VerifyCsrf::class"), 'State-changing routes use CSRF middleware');
check(str_contains($routes, "new RequireRole(['admin'])"), 'Admin route requires the exact Admin role');
check(str_contains($routes, "new RequireRole(['security_admin'])"), 'Security route requires the exact Security Admin role');
check(str_contains($headers, 'Content-Security-Policy:'), 'A Content Security Policy is emitted');
check(str_contains(source('app/Core/Database.php'), 'PDO::ATTR_EMULATE_PREPARES => false'), 'PDO emulated prepares are disabled');

$requiredTables = [
    'users', 'documents', 'user_activity', 'security_events', 'security_sessions',
    'decoy_endpoints', 'honeytokens', 'vulnerability_modules', 'vulnerability_state_changes',
];
foreach ($requiredTables as $table) {
    check((bool) preg_match('/CREATE TABLE\s+' . preg_quote($table, '/') . '\s*\(/i', $schema), "Schema defines {$table}");
}

check(!str_contains(source('database/seed.sql'), 'AKIA'), 'Seed does not contain AWS-style access-key material');
$gitignore = source('.gitignore');
check(
    is_file($root . '/.env.example') && (bool) preg_match('/^\/\.env\s*$/m', $gitignore),
    'Environment template exists and the local secret file is ignored'
);

echo "\n{$passes} checks passed, " . count($failures) . " failed.\n";
exit($failures === [] ? 0 : 1);
