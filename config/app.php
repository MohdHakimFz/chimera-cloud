<?php
return [
    'name' => env('APP_NAME', 'CHIMERA CLOUD'),
    'environment' => env('APP_ENV', 'production'),
    'debug' => env_bool('APP_DEBUG', false),
    'url' => env('APP_URL', ''),
    'base_path' => env('APP_BASE_PATH', ''),
    'timezone' => env('APP_TIMEZONE', 'UTC'),
    'vulnerability_lab_enabled' => env_bool('VULNERABILITY_LAB_ENABLED', false),
];
