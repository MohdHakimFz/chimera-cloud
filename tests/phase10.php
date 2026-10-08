<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/app.php';

use App\Services\HostingCapabilityInspector;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$root = dirname(__DIR__);
$allExtensions = array_fill_keys(array_map('strtolower', HostingCapabilityInspector::REQUIRED_EXTENSIONS), true);
$normal = HostingCapabilityInspector::inspect([], $allExtensions, [
    'upload_max_filesize' => '8M',
    'post_max_size' => '8M',
    'memory_limit' => '128M',
    'max_execution_time' => '30',
]);
$missing = $allExtensions;
$missing['pdo_mysql'] = false;
$blocked = HostingCapabilityInspector::inspect([], $missing, [
    'upload_max_filesize' => '8M',
    'post_max_size' => '8M',
    'memory_limit' => '128M',
    'max_execution_time' => '30',
]);

$check(HostingCapabilityInspector::REQUIRED_EXTENSIONS === ['PDO', 'pdo_mysql', 'mbstring', 'fileinfo', 'json', 'session', 'hash'], 'Hosting preflight declares only source-required PHP extensions');
$check($normal['status'] === 'HOSTING-DEPENDENT', 'Local CLI preflight preserves unresolved hosting items');
$check($blocked['status'] === 'BLOCKED', 'Missing required extension blocks deployment preflight');
$check(array_filter($blocked['checks'], static fn (array $row): bool => $row['id'] === 'extension_pdo_mysql' && $row['status'] === 'BLOCKED') !== [], 'Missing PDO MySQL is identified precisely');
$check(array_filter($normal['checks'], static fn (array $row): bool => $row['id'] === 'https_indicator' && $row['status'] === 'HOSTING-DEPENDENT') !== [], 'HTTPS remains hosting-dependent without live server evidence');
$check(array_filter($normal['checks'], static fn (array $row): bool => $row['id'] === 'database_service' && $row['status'] === 'HOSTING-DEPENDENT') !== [], 'Production database details are never guessed locally');

$script = file_get_contents($root . '/scripts/phase10-hosting-preflight.php');
$check(str_contains($script, "PHP_SAPI !== 'cli'"), 'Hosting preflight script is CLI-only');
$check(!preg_match('/\b(?:curl_exec|fsockopen|stream_socket_client)\s*\(/', $script), 'Hosting preflight performs no external network operation');
$check(!preg_match('/(?:DB_PASSWORD|TELEMETRY_HASH_KEY).*echo/i', $script), 'Hosting preflight does not print secret configuration values');
$check(str_contains($script, 'Secret values are intentionally omitted'), 'Hosting preflight explicitly states secret omission');

$validation = file_get_contents($root . '/docs/PHASE10_VALIDATION.md');
$pentest = file_get_contents($root . '/docs/PENTEST_EXECUTION_PLAN.md');
$hostinger = file_get_contents($root . '/docs/HOSTINGER_DEPLOYMENT_PLAN.md');
$check(str_contains($validation, 'BLOCKED ON DEPLOYMENT ACCESS'), 'Validation record reports the honest deployment-access checkpoint');
$check(str_contains($validation, 'NORMAL_SAFE'), 'Validation record requires NORMAL_SAFE first deployment');
$check(str_contains($validation, 'separate explicit authorization'), 'Lab activation remains separately authorized');
$check(str_contains($pentest, 'OUT OF SCOPE'), 'Pentest handoff defines out-of-scope systems');
$check(str_contains($pentest, 'Do not execute'), 'Pentest plan does not authorize automatic execution');
$check(str_contains($pentest, 'exact authorized CHIMERA origin'), 'Pentest plan scopes activity to one confirmed origin');
$check(str_contains($hostinger, 'Stage A') && str_contains($hostinger, 'Stage E'), 'Hostinger plan preserves all five ordered deployment stages');
$check(str_contains(file_get_contents($root . '/docs/DEPLOYMENT_CHECKLIST.md'), 'NORMAL_SAFE checkpoint'), 'Deployment checklist contains the mandatory lab-off checkpoint');

$sensitive = implode("\n", [$script, $validation, $pentest, $hostinger]);
$check(!preg_match('/(?:DB_PASSWORD|TELEMETRY_HASH_KEY)\s*=\s*[^<\s][^\r\n]*/', $sensitive), 'Phase 10 artifacts contain no assigned secret values');
$check(!preg_match('/\b(?:nmap|nikto|ffuf|gobuster)\b.*(?:--|-)target\s+(?!<|\$)/i', $pentest), 'Pentest examples contain no fabricated live target');

echo "\n{$passed} Phase 10 preparation checks passed, {$failed} failed.\n";
exit($failed === 0 ? 0 : 1);
