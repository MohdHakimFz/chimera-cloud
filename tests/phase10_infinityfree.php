<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/app.php';

use App\Services\DocumentStorage;
use App\Services\ProductionSecurityValidator;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$root = dirname(__DIR__);
$policy = (string) file_get_contents($root . '/.htaccess');
$privateRule = strpos($policy, 'app|bootstrap|config|database|deployment|docs|evidence|resources|routes|scripts|storage|tests|vendor|logs');
$fileBypass = strpos($policy, '%{REQUEST_FILENAME} !-f');

$check(str_contains($policy, 'CHIMERA_INFINITYFREE_PROTECTED_ROOT'), 'Root policy identifies the protected InfinityFree topology');
$check($privateRule !== false && $fileBypass !== false && $privateRule < $fileBypass, 'Private-path denial precedes file and directory bypass rules');
$check(str_contains($policy, 'THE_REQUEST') && str_contains($policy, 'RewriteRule ^public'), 'Direct public/ URLs are denied without blocking internal rewrites');
$rootRoute = strpos($policy, 'RewriteRule ^$ public/index.php [QSA,L]');
$directoryBypass = strpos($policy, '%{REQUEST_FILENAME} !-d');
$check($rootRoute !== false && $directoryBypass !== false && $rootRoute < $directoryBypass, 'Origin root is routed before the real-directory bypass can produce a provider 403');
$check(str_contains($policy, 'RewriteRule ^assets/css/') && str_contains($policy, 'RewriteRule ^assets/js/') && str_contains($policy, 'RewriteRule ^assets/images/'), 'Asset mapping uses allowlisted static families');
$check(str_contains($policy, '\\.css)') && str_contains($policy, '\\.js)') && str_contains($policy, 'svg|webp'), 'Asset mapping constrains extensions by asset family');
$check(!str_contains($policy, 'RewriteRule ^assets/(.*)'), 'Asset mapping has no arbitrary path capture');
$check(str_contains($policy, 'RewriteRule ^ public/index.php [QSA,L]'), 'Origin-root application routes use public/index.php internally');
$check(str_contains($policy, 'FilesMatch') && str_contains($policy, 'env|ini|log|sql|bak|backup|old|orig|save|dist|tmp|temp|swp|swo'), 'Sensitive and temporary file extensions are denied');
$check(str_contains($policy, '\\.git|\\.github|\\.vscode|\\.idea'), 'Repository and editor metadata paths are denied');
$check(str_contains((string) file_get_contents($root . '/storage/.htaccess'), 'Require all denied'), 'Storage retains complete HTTP denial');
$check(str_contains((string) file_get_contents($root . '/storage/uploads/.htaccess'), 'phtml|phar'), 'Upload storage retains executable-extension denial');

$base = [
    'APP_ENV'=>'production','APP_DEBUG'=>'false','APP_URL'=>'https://projectchimera.infinityfreeapp.com','HTTPS_ENFORCE'=>'true',
    'SESSION_SECURE'=>'true','SESSION_SAMESITE'=>'Lax','TELEMETRY_HASH_KEY'=>str_repeat('x',32),
    'DB_HOST'=>'sql.example.invalid','DB_PORT'=>'3306','DB_DATABASE'=>'production_placeholder','DB_USERNAME'=>'runtime_placeholder','DB_PASSWORD'=>'unit-only-placeholder',
    'DOCUMENT_STORAGE_PATH'=>$root.'/storage/uploads/documents','DOCUMENT_MAX_BYTES'=>'5242880','DOCUMENT_ALLOWED_EXTENSIONS'=>'pdf,txt,csv,md',
    'DEPLOYMENT_STORAGE_MODE'=>'PROTECTED_IN_WEBROOT','WEBROOT_DENIAL_VERIFIED'=>'false','VULNERABILITY_LAB_ENABLED'=>'false',
];
$pending = ProductionSecurityValidator::evaluate($base, [], false);
$pendingChecks = array_column($pending['checks'], null, 'id');
$check($pending['status'] === 'FAIL' && $pending['gate'] === 'BLOCKED', 'Protected mode remains deployment-blocking before live denial verification');
$check(($pendingChecks['private_storage']['status'] ?? '') === 'PASS', 'Protected mode accepts only the exact statically protected document path');
$check(($pendingChecks['webroot_denial_live']['status'] ?? '') === 'FAIL' && str_contains($pendingChecks['webroot_denial_live']['detail'] ?? '', 'PENDING LIVE VERIFICATION'), 'Readiness explicitly reports pending live web denial');
$check(($pendingChecks['env_location']['status'] ?? '') === 'PASS', 'Readiness recognizes static dotfile denial separately from live verification');
$verified = ProductionSecurityValidator::evaluate([...$base, 'WEBROOT_DENIAL_VERIFIED'=>'true'], [], false);
$check($verified['status'] === 'PASS' && $verified['gate'] === 'NORMAL_MODE_READY', 'Protected mode can pass only after the operator records live denial verification');
$missingPort = ProductionSecurityValidator::evaluate([...$base, 'DB_PORT'=>''], [], false);
$check($missingPort['status'] === 'FAIL', 'Unknown production database port remains deployment-blocking');

$oldMode = getenv('DEPLOYMENT_STORAGE_MODE');
$oldPath = getenv('DOCUMENT_STORAGE_PATH');
putenv('DEPLOYMENT_STORAGE_MODE=PROTECTED_IN_WEBROOT');
putenv('DOCUMENT_STORAGE_PATH='.$root.'/storage/uploads/documents');
try {
    $check(DocumentStorage::root() !== '', 'Document storage permits only the protected runtime path in protected mode');
    $check(DocumentStorage::isInsidePublicRoot($root.'/storage/uploads/documents'), 'Protected mode accurately recognizes storage as web-root-resident');
    $check(DocumentStorage::isProtectedInWebrootPath($root.'/storage/uploads/documents'), 'Protected mode recognizes the exact guarded document root');
    $check(!DocumentStorage::isProtectedInWebrootPath($root.'/public/assets'), 'Protected mode never treats public assets as private document storage');
    putenv('DOCUMENT_STORAGE_PATH='.$root.'/public/assets');
    $rejected = false;
    try { DocumentStorage::root(); } catch (RuntimeException) { $rejected = true; }
    $check($rejected, 'Protected mode rejects document storage under public assets');
} finally {
    $oldMode === false ? putenv('DEPLOYMENT_STORAGE_MODE') : putenv('DEPLOYMENT_STORAGE_MODE='.$oldMode);
    $oldPath === false ? putenv('DOCUMENT_STORAGE_PATH') : putenv('DOCUMENT_STORAGE_PATH='.$oldPath);
}

$seed = (string) file_get_contents($root . '/database/production_reference_seed.sql');
$check(substr_count($seed, 'INSERT INTO decoy_endpoints') === 3, 'Production reference seed defines exactly three decoys');
$check(substr_count($seed, 'INSERT INTO honeytokens') === 2, 'Production reference seed defines exactly two honeytokens');
$check(substr_count($seed, 'INSERT INTO vulnerability_modules') === 3, 'Production reference seed defines exactly three vulnerability modules');
$check(substr_count($seed, "'REMEDIATED',1") === 3, 'All production vulnerability modules start REMEDIATED');
$check(!preg_match('/INSERT\s+INTO\s+(users|documents|user_activity|security_events|security_sessions|security_score_contributors|honeytoken_events|vulnerability_state_changes)\b/i', $seed), 'Production reference seed inserts no operational or identity data');
$check(!preg_match('/password|password_hash|@e2e\.chimera\.test/i', $seed), 'Production reference seed contains no passwords, hashes, or E2E identities');
$check(substr_count($seed, 'WHERE NOT EXISTS') === 8, 'All eight reference inserts are safely idempotent without updating existing rows');
$schema = (string) file_get_contents($root . '/database/schema.sql');
$check(str_contains($schema, 'INITIALIZATION ONLY') && str_contains($schema, 'explicit destructive-reset decision'), 'Schema declares its destructive initialization-only boundary');

$environment = (string) file_get_contents($root . '/.env.infinityfree.example');
$check(str_contains($environment, 'APP_ENV=production') && str_contains($environment, 'APP_DEBUG=false') && str_contains($environment, 'VULNERABILITY_LAB_ENABLED=false'), 'InfinityFree template enforces NORMAL_SAFE baseline values');
$check(str_contains($environment, 'DB_PORT=3306') && !str_contains($environment, 'DB_PORT=3308'), 'InfinityFree template uses the provider-confirmed port and never the local database port');
$check(str_contains($environment, 'DB_PASSWORD=<OPERATOR_SECRET>') && !preg_match('/^TEST_DB_/m', $environment), 'InfinityFree template uses a password placeholder and no test database settings');
$check(str_contains($environment, 'DEPLOYMENT_STORAGE_MODE=PROTECTED_IN_WEBROOT') && str_contains($environment, 'WEBROOT_DENIAL_VERIFIED=false'), 'InfinityFree template starts protected mode with live verification false');

$capability = (string) file_get_contents($root . '/deployment/infinityfree-capability-check.php');
$check(str_contains($capability, 'CHIMERA_TEMP_CAPABILITY_CHECK_ENABLED = false'), 'Temporary capability checker is disabled by default');
$check(!str_contains($capability, 'phpinfo(') && !preg_match('/\b(getenv|\$_ENV|\$_SERVER|\$_COOKIE|session_id)\b/', $capability), 'Capability checker exposes no environment, headers, cookies, sessions, or phpinfo');
$check(substr_count($capability, 'extension_loaded') === 1 && str_contains($capability, "'pdo_mysql'") && str_contains($capability, "'fileinfo'"), 'Capability checker reports only the required extension set');

$manifest = json_decode((string) file_get_contents($root . '/deployment/infinityfree-manifest.json'), true, 32, JSON_THROW_ON_ERROR);
$check(($manifest['layout'] ?? '') === 'INFINITYFREE_HTDOCS_PROTECTED', 'Machine-readable manifest identifies the protected htdocs layout');
$check(in_array('public/index.php', $manifest['upload'] ?? [], true) && in_array('storage/.htaccess', $manifest['upload'] ?? [], true), 'Manifest uploads the front controller and storage denial policy');
$check(in_array('database/', $manifest['do_not_upload'] ?? [], true) && in_array('.env', $manifest['do_not_upload'] ?? [], true) && in_array('deployment/', $manifest['do_not_upload'] ?? [], true), 'Manifest excludes database artifacts, environment secrets, and temporary deployment tools');
$check(count($manifest['operator_configures_manually'] ?? []) === 5, 'Manifest contains the five manual operator responsibilities');
$probe = (string) file_get_contents($root . '/deployment/infinityfree-env-denial-probe.txt');
$check(str_contains($probe, 'NON_SECRET_CANARY') && !preg_match('/password|token|private[_ -]?key/i', $probe), 'Environment denial probe is an explicit non-secret canary');
$check(count($manifest['temporary_only'] ?? []) === 2 && str_contains(implode(' ', $manifest['temporary_only']), 'then delete'), 'Manifest marks both diagnostics as temporary and requires probe deletion');

$routes = (string) file_get_contents($root . '/routes/web.php');
$check(!preg_match('/\$router->(?:get|post)\([^\n]*(?:promote|setRole|changeRole|role-update)/i', $routes), 'No HTTP role-promotion route was introduced');

echo "\n{$passed} InfinityFree compatibility checks passed, {$failed} failed.\n";
exit($failed === 0 ? 0 : 1);
