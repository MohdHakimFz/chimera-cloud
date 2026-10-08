<?php

declare(strict_types=1);

try {
    $app = require dirname(__DIR__) . '/bootstrap/app.php';
    require BASE_PATH . '/routes/web.php';
    $app->run();
} catch (Throwable $exception) {
    error_log('CHIMERA bootstrap failure: '.$exception::class);
    http_response_code(500);
    header('Cache-Control: no-store');
    $path=(string)(parse_url($_SERVER['REQUEST_URI']??'/',PHP_URL_PATH)?:'/');
    if($path==='/api'||str_starts_with($path,'/api/')){header('Content-Type: application/json; charset=utf-8');echo '{"error":{"code":"SERVER_ERROR","message":"The request could not be completed."}}';}else{header('Content-Type: text/html; charset=utf-8');echo '<!doctype html><html lang="en"><meta charset="utf-8"><title>Application error</title><body><h1>Application error</h1><p>The request could not be completed.</p></body></html>';}
}
