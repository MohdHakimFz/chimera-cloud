<?php
return [
    'session' => [
        'name' => env('SESSION_NAME', 'chimera_session'),
        'secure' => env_bool('SESSION_SECURE', true),
        'same_site' => env('SESSION_SAMESITE', 'Lax'),
        'lifetime' => (int) env('SESSION_LIFETIME', 7200),
    ],
    'roles' => ['user', 'admin', 'security_admin'],
    'password_minimum_length' => 12,
];

