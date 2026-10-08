<?php

declare(strict_types=1);

namespace App\Services;

use RuntimeException;

final class DocumentStorage
{
    public const PRIVATE_OUTSIDE_WEBROOT = 'PRIVATE_OUTSIDE_WEBROOT';
    public const PROTECTED_IN_WEBROOT = 'PROTECTED_IN_WEBROOT';

    public static function root(): string
    {
        $configured = trim((string) env('DOCUMENT_STORAGE_PATH', ''));
        if ($configured !== '' && !self::isAbsolutePath($configured)) {
            throw new RuntimeException('Configured document storage path must be absolute.');
        }
        $root = $configured !== '' ? self::canonicalRoot($configured) : BASE_PATH . '/storage/uploads/documents';
        $root = realpath($root) ?: $root;
        $root = rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $root), DIRECTORY_SEPARATOR);
        if ($root === '' || (self::isInsidePublicRoot($root) && !self::isProtectedInWebrootPath($root))) {
            throw new RuntimeException('Document storage must be outside the public web root.');
        }
        return $root;
    }

    public static function ensureDirectories(): void
    {
        foreach ([self::root(), self::root() . DIRECTORY_SEPARATOR . '.trash'] as $directory) {
            if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
                throw new RuntimeException('Document storage directory could not be created.');
            }
        }
    }

    public static function path(string $storageName): string
    {
        if (!preg_match('/\A[a-f0-9]{48}\.(pdf|txt|csv|md)\z/', $storageName)) {
            throw new RuntimeException('Invalid internal document filename.');
        }
        return self::root() . DIRECTORY_SEPARATOR . $storageName;
    }

    public static function trashPath(string $storageName): string
    {
        return self::root() . DIRECTORY_SEPARATOR . '.trash' . DIRECTORY_SEPARATOR . $storageName . '.' . bin2hex(random_bytes(8));
    }

    public static function isInsidePublicRoot(string $path, ?string $mode = null): bool
    {
        $mode ??= self::protectionMode();
        $webRoot = $mode === self::PROTECTED_IN_WEBROOT ? BASE_PATH : BASE_PATH . '/public';
        $public = self::normalize($webRoot);
        $candidate = strtolower(rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path), DIRECTORY_SEPARATOR));
        return $candidate === $public || str_starts_with($candidate . DIRECTORY_SEPARATOR, $public . DIRECTORY_SEPARATOR);
    }

    public static function protectionMode(): string
    {
        $mode = strtoupper(trim((string) env('DEPLOYMENT_STORAGE_MODE', self::PRIVATE_OUTSIDE_WEBROOT)));
        return $mode === self::PROTECTED_IN_WEBROOT ? self::PROTECTED_IN_WEBROOT : self::PRIVATE_OUTSIDE_WEBROOT;
    }

    public static function isProtectedInWebrootPath(string $path, ?string $mode = null): bool
    {
        $mode ??= self::protectionMode();
        if ($mode !== self::PROTECTED_IN_WEBROOT || !self::hasStaticWebDenialControls()) {
            return false;
        }
        return self::normalize($path) === self::normalize(BASE_PATH . '/storage/uploads/documents');
    }

    public static function hasStaticWebDenialControls(): bool
    {
        $rootPolicy = @file_get_contents(BASE_PATH . '/.htaccess');
        $storagePolicy = @file_get_contents(BASE_PATH . '/storage/.htaccess');
        $uploadPolicy = @file_get_contents(BASE_PATH . '/storage/uploads/.htaccess');
        return is_string($rootPolicy)
            && str_contains($rootPolicy, 'CHIMERA_INFINITYFREE_PROTECTED_ROOT')
            && str_contains($rootPolicy, 'storage')
            && is_string($storagePolicy)
            && str_contains($storagePolicy, 'Require all denied')
            && is_string($uploadPolicy)
            && str_contains($uploadPolicy, 'Require all denied');
    }

    public static function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, '/') || (bool) preg_match('/\A[A-Za-z]:[\\\\\/]/', $path) || str_starts_with($path, '\\\\');
    }

    private static function canonicalRoot(string $path): string
    {
        $existing = realpath($path);
        if ($existing !== false) {
            return $existing;
        }

        $parent = realpath(dirname($path));
        if ($parent === false) {
            throw new RuntimeException('Configured document storage parent directory must exist.');
        }

        $name = basename($path);
        if ($name === '' || $name === '.' || $name === '..') {
            throw new RuntimeException('Configured document storage path is invalid.');
        }
        return $parent . DIRECTORY_SEPARATOR . $name;
    }

    private static function normalize(string $path): string
    {
        return strtolower(rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path), DIRECTORY_SEPARATOR));
    }
}
