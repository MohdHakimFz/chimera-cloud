<?php

declare(strict_types=1);

namespace App\Core;

final class Response
{
    public static function view(string $view, array $data = [], int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, private, max-age=0');
        View::render($view, $data);
        exit;
    }

    public static function standaloneView(string $view, array $data = [], int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        View::renderStandalone($view, $data);
        exit;
    }

    public static function redirect(string $path, int $status = 302): never
    {
        header('Cache-Control: no-store, private, max-age=0');
        header('Location: ' . url($path), true, $status);
        exit;
    }

    public static function json(array $payload, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        exit;
    }

    public static function download(string $path, string $originalName, string $mimeType): never
    {
        $fallback = preg_replace('/[^A-Za-z0-9._-]/', '_', $originalName) ?: 'document';
        $fallback = trim($fallback, '.');
        if ($fallback === '') {
            $fallback = 'document';
        }

        http_response_code(200);
        header('Content-Type: ' . $mimeType);
        header('Content-Length: ' . (string) filesize($path));
        header('Content-Disposition: attachment; filename="' . $fallback . '"; filename*=UTF-8\'\'' . rawurlencode($originalName));
        header('Cache-Control: private, no-store, max-age=0');
        header('Pragma: no-cache');
        readfile($path);
        exit;
    }

    public static function abort(int $status, string $message = ''): never
    {
        http_response_code($status);
        $view = is_file(BASE_PATH . "/resources/views/errors/{$status}.php") ? "errors/{$status}" : 'errors/500';
        View::render($view, ['message' => $message]);
        exit;
    }
}
