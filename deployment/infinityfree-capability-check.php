<?php

declare(strict_types=1);

// Temporary diagnostic only. Keep false in the repository and final deployment package.
const CHIMERA_TEMP_CAPABILITY_CHECK_ENABLED = false;

if (!CHIMERA_TEMP_CAPABILITY_CHECK_ENABLED) {
    http_response_code(404);
    exit;
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private, max-age=0');
header('X-Content-Type-Options: nosniff');

$root = is_dir(__DIR__ . '/storage') ? __DIR__ : dirname(__DIR__);
$extensions = ['PDO', 'pdo_mysql', 'mbstring', 'fileinfo', 'json', 'session', 'hash'];
$availability = [];
foreach ($extensions as $extension) {
    $availability[$extension] = extension_loaded($extension);
}

$writable = [];
foreach (['logs' => 'storage/logs', 'sessions' => 'storage/sessions', 'uploads' => 'storage/uploads'] as $label => $relative) {
    $writable[$label] = is_dir($root . '/' . $relative) && is_writable($root . '/' . $relative);
}

echo json_encode([
    'temporary_check' => true,
    'php_version' => PHP_VERSION,
    'extensions' => $availability,
    'runtime_directories_writable' => $writable,
    'remove_immediately_after_verification' => true,
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
