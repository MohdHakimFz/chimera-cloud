<?php

declare(strict_types=1);

namespace App\Core;

use RuntimeException;

final class View
{
    public static function render(string $view, array $data = []): void
    {
        $viewFile = BASE_PATH . '/resources/views/' . str_replace('.', '/', $view) . '.php';
        if (!is_file($viewFile)) {
            throw new RuntimeException("View [{$view}] was not found.");
        }

        extract($data, EXTR_SKIP);
        ob_start();
        require $viewFile;
        $content = (string) ob_get_clean();
        require BASE_PATH . '/resources/views/layouts/app.php';
        Session::forget('_old');
        Session::forget('_errors');
    }

    public static function renderStandalone(string $view, array $data = []): void
    {
        $viewFile = BASE_PATH . '/resources/views/' . str_replace('.', '/', $view) . '.php';
        if (!is_file($viewFile)) {
            throw new RuntimeException("View [{$view}] was not found.");
        }
        extract($data, EXTR_SKIP);
        require $viewFile;
    }
}
