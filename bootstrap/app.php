<?php

declare(strict_types=1);

use App\Core\Application;
use App\Core\Env;
use App\Core\Session;
use App\Security\SecurityHeaders;

define('BASE_PATH', dirname(__DIR__));

spl_autoload_register(static function (string $class): void {
    $prefix = 'App\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $file = BASE_PATH . '/app/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

require BASE_PATH . '/app/Helpers/functions.php';

Env::load(BASE_PATH . '/.env');
date_default_timezone_set((string) env('APP_TIMEZONE', 'UTC'));

error_reporting(E_ALL);
$production = strtolower((string) env('APP_ENV', 'production')) === 'production';
ini_set('display_errors', !$production && env_bool('APP_DEBUG', false) ? '1' : '0');
ini_set('log_errors', '1');
ini_set('error_log', BASE_PATH . '/storage/logs/application.log');

Session::start();
SecurityHeaders::send();

return new Application();
