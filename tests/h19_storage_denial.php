<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Services\DocumentStorage;
use App\Services\ProductionSecurityValidator;
use App\Services\ThreatScoringService;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$read = static fn (string $path): string => (string) file_get_contents($root . '/' . $path);

$policy = $read('.htaccess');
$publicPolicy = $read('public/.htaccess');
$storagePolicy = $read('storage/.htaccess');
$uploadPolicy = $read('storage/uploads/.htaccess');
$routes = $read('routes/web.php');
$storageSource = $read('app/Services/DocumentStorage.php');
$uploadSource = $read('app/Security/UploadValidator.php');
$manifest = json_decode($read('deployment/infinityfree-manifest.json'), true, 32, JSON_THROW_ON_ERROR);

$matched = preg_match('/^\s*RewriteRule\s+\^(.+?)\s+-\s+\[F,L,NC\]\s*$/m', $policy, $ruleMatch) === 1;
$storageRule = $matched ? $ruleMatch[0] : '';
$apachePattern = $matched ? '~^' . $ruleMatch[1] . '~i' : '~a^~';
$check($matched && str_contains($storageRule, 'storage'), 'Root policy contains an explicit forbidden storage-subtree rule');

$denyPosition = strpos($policy, $storageRule);
$publicPosition = strpos($policy, 'RewriteCond %{THE_REQUEST}');
$assetPosition = strpos($policy, 'RewriteRule ^assets/css/');
$filePosition = strpos($policy, 'RewriteCond %{REQUEST_FILENAME} !-f');
$directoryPosition = strpos($policy, 'RewriteCond %{REQUEST_FILENAME} !-d');
$frontPosition = strpos($policy, 'RewriteRule ^ public/index.php');
$check(
    $denyPosition !== false
    && $publicPosition !== false && $denyPosition < $publicPosition
    && $assetPosition !== false && $denyPosition < $assetPosition
    && $filePosition !== false && $denyPosition < $filePosition
    && $directoryPosition !== false && $denyPosition < $directoryPosition
    && $frontPosition !== false && $denyPosition < $frontPosition,
    'Storage denial precedes public handling, assets, file/directory bypass, and front-controller routing'
);
$check(str_contains($storageRule, '[F,L,NC]'), 'Root storage denial uses forbidden, last, and case-insensitive semantics');

$coveredPaths = [
    'storage',
    'storage/',
    'storage/uploads',
    'storage/uploads/',
    'storage/uploads/documents',
    'storage/uploads/documents/',
    'storage/uploads/documents/' . str_repeat('a', 48) . '.txt',
    'storage/uploads/documents/.trash/' . str_repeat('b', 48) . '.txt.' . str_repeat('c', 16),
    'STORAGE/UPLOADS/DOCUMENTS/' . str_repeat('d', 48) . '.TXT/path-info',
];
foreach ($coveredPaths as $path) {
    $check(preg_match($apachePattern, $path) === 1, "Root denial grammar covers {$path}");
}
$check(preg_match($apachePattern, 'assets/css/app.css') === 0 && preg_match($apachePattern, 'documents/1') === 0, 'Storage denial grammar does not capture public assets or application document routes');
$check(str_contains($policy, 'Options -Indexes'), 'Root policy disables directory indexes');
$check(str_contains($storagePolicy, 'Options -Indexes') && str_contains($storagePolicy, 'Require all denied'), 'Storage-local policy disables indexes and denies all HTTP access');
$check(str_contains($uploadPolicy, 'Options -Indexes') && str_contains($uploadPolicy, 'Require all denied'), 'Upload-local policy repeats index and total-access denial');
$check((bool) preg_match('/php\[0-9\]\?|phtml|phar|cgi|pl|py|sh/i', $uploadPolicy), 'Upload-local policy denies executable and script extensions');
$check(in_array('storage/.htaccess', $manifest['upload'] ?? [], true) && in_array('storage/uploads/.htaccess', $manifest['upload'] ?? [], true), 'InfinityFree manifest deploys both storage denial policies');
$check(in_array('storage/uploads/documents/.gitkeep', $manifest['upload'] ?? [], true) && in_array('storage/uploads/documents/.trash/.gitkeep', $manifest['upload'] ?? [], true), 'Manifest preserves the intended active and trash directory topology');

$base = [
    'APP_ENV'=>'production','APP_DEBUG'=>'false','APP_URL'=>'https://chimera.invalid','HTTPS_ENFORCE'=>'true',
    'SESSION_SECURE'=>'true','SESSION_SAMESITE'=>'Lax','TELEMETRY_HASH_KEY'=>str_repeat('h', 32),
    'DB_HOST'=>'db.invalid','DB_PORT'=>'3306','DB_DATABASE'=>'chimera','DB_USERNAME'=>'chimera_app','DB_PASSWORD'=>'placeholder-only',
    'DOCUMENT_STORAGE_PATH'=>$root . '/storage/uploads/documents','DOCUMENT_MAX_BYTES'=>'5242880',
    'DOCUMENT_ALLOWED_EXTENSIONS'=>'pdf,txt,csv,md','DEPLOYMENT_STORAGE_MODE'=>'PROTECTED_IN_WEBROOT',
    'VULNERABILITY_LAB_ENABLED'=>'false',
];
$pending = ProductionSecurityValidator::evaluate([...$base, 'WEBROOT_DENIAL_VERIFIED'=>'false'], [], false);
$verified = ProductionSecurityValidator::evaluate([...$base, 'WEBROOT_DENIAL_VERIFIED'=>'true'], [], false);
$pendingChecks = array_column($pending['checks'], null, 'id');
$verifiedChecks = array_column($verified['checks'], null, 'id');
$check(($pendingChecks['private_storage']['status'] ?? '') === 'PASS', 'Protected mode accepts the exact intended logical storage topology');
$check(($pendingChecks['webroot_denial_live']['status'] ?? '') === 'FAIL' && ($pending['gate'] ?? '') === 'BLOCKED', 'Production readiness fails closed until live webroot denial is attested');
$check(($verifiedChecks['webroot_denial_live']['status'] ?? '') === 'PASS', 'Recorded live denial is represented separately from static storage controls');
$check(str_contains($storageSource, "BASE_PATH . '/storage/uploads/documents'") && str_contains($storageSource, "BASE_PATH . '/storage/.htaccess'") && str_contains($storageSource, "BASE_PATH . '/storage/uploads/.htaccess'"), 'DocumentStorage binds protected mode to the exact logical root and both local denial policies');

$check(!preg_match('/\$router->(?:get|post)\(\'\/storage(?:\/|\')/i', $routes), 'No application route exposes the storage subtree');
$check(!preg_match('/RewriteRule\s+\^storage.+public\//i', $policy), 'No public static alias maps the storage subtree');
$check(str_contains($policy, 'THE_REQUEST') && str_contains($policy, 'RewriteRule ^public(?:/|$) - [F,L,NC]'), 'Direct public-prefix protection remains present');
$check((bool) preg_match('/<FilesMatch[^>]+env\|ini\|log\|sql.*Require all denied/is', $policy), 'Sensitive extension and dotfile denial remains present');
$check(str_contains($publicPolicy, '<FilesMatch "^\\.">') && str_contains($publicPolicy, 'Require all denied'), 'Public defense-in-depth denies dotfiles');

$check(str_contains($uploadSource, "'pdf'") && str_contains($uploadSource, "'txt'") && str_contains($uploadSource, "'csv'") && str_contains($uploadSource, "'md'"), 'Upload MIME map remains limited to approved document formats');
$check(str_contains($uploadSource, 'php[0-9]?|phtml|phar|cgi|pl|py|sh'), 'Application upload validation rejects executable and script suffixes');
$check(str_contains($storageSource, "[a-f0-9]{48}\\.(pdf|txt|csv|md)"), 'Internal storage names cannot acquire arbitrary executable extensions');
$check(ThreatScoringService::weight('OWNERSHIP_ACCESS_DENIED') === 12 && ThreatScoringService::weight('CSRF_REJECTED') === 12, 'H14/H17 ownership and CSRF scoring invariants remain exactly +12');
$check((string) env('VULNERABILITY_LAB_ENABLED', 'false') !== 'true', 'Vulnerability LAB remains disabled by default');

$h19Sources = implode("\n", array_map(static fn (string $path): string => is_file($path) ? (string) file_get_contents($path) : '', glob($root . '/tests/h19_*.php') ?: []));
$productionOrigin = 'projectchimera.' . 'infinityfreeapp.com';
$retainedCredentialMarker = 'DPA' . 'PI';
$privateKeyMarker = 'BEGIN ' . 'PRIVATE KEY';
$check(!str_contains($h19Sources, $productionOrigin) && !str_contains($h19Sources, $retainedCredentialMarker) && !str_contains($h19Sources, $privateKeyMarker), 'H19 tests contain no production origin, retained credential material, or private key');

echo PHP_EOL . "{$passed} H19 static storage-denial checks passed, {$failed} failed, 0 skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
