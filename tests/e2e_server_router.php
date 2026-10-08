<?php

declare(strict_types=1);

$testRoot = dirname(__DIR__);
require_once $testRoot . '/app/Core/Env.php';
\App\Core\Env::load($testRoot . '/.env');

if ((string) getenv('TEST_DB_DATABASE') !== 'chimera_test') {
    http_response_code(500);
    echo 'Test database safety guard failed.';
    return true;
}

$testUsername = (string) getenv('TEST_DB_USERNAME');
$testPassword = (string) getenv('TEST_DB_PASSWORD');
if ($testUsername === '' || $testPassword === '') {
    http_response_code(500);
    echo 'Dedicated test credentials are unavailable.';
    return true;
}

putenv('DB_HOST=127.0.0.1');
$_ENV['DB_HOST'] = '127.0.0.1';
putenv('DB_PORT=3308');
$_ENV['DB_PORT'] = '3308';
putenv('DB_DATABASE=chimera_test');
$_ENV['DB_DATABASE'] = 'chimera_test';
putenv('DB_USERNAME=' . $testUsername);
$_ENV['DB_USERNAME'] = $testUsername;
putenv('DB_PASSWORD=' . $testPassword);
$testPasswordValue = $testPassword;
$_ENV['DB_PASSWORD'] = $testPasswordValue;
$e2eBaseUrl = (string) getenv('CHIMERA_E2E_BASE_URL');
putenv('APP_URL=' . $e2eBaseUrl);
$_ENV['APP_URL'] = $e2eBaseUrl;
putenv('APP_DEBUG=false');
$_ENV['APP_DEBUG'] = 'false';
putenv('SESSION_SECURE=false');
$_ENV['SESSION_SECURE'] = 'false';
$e2eStorage = (string) getenv('CHIMERA_E2E_STORAGE');
putenv('DOCUMENT_STORAGE_PATH=' . $e2eStorage);
$_ENV['DOCUMENT_STORAGE_PATH'] = $e2eStorage;
putenv('DOCUMENT_MAX_BYTES=1024');
$_ENV['DOCUMENT_MAX_BYTES'] = '1024';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$candidate = realpath($testRoot . '/public' . str_replace('/', DIRECTORY_SEPARATOR, $path));
$publicRoot = realpath($testRoot . '/public');
if ($candidate !== false && $publicRoot !== false && str_starts_with(strtolower($candidate), strtolower($publicRoot . DIRECTORY_SEPARATOR)) && is_file($candidate)) {
    return false;
}

require $testRoot . '/public/index.php';
return true;
