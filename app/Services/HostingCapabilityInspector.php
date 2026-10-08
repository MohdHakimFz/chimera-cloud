<?php

declare(strict_types=1);

namespace App\Services;

use App\Security\TransportSecurity;

/**
 * Read-only hosting preflight. Results intentionally exclude paths and secrets.
 */
final class HostingCapabilityInspector
{
    public const REQUIRED_EXTENSIONS = ['PDO', 'pdo_mysql', 'mbstring', 'fileinfo', 'json', 'session', 'hash'];

    public static function inspect(
        array $server = [],
        ?array $extensionState = null,
        ?array $iniValues = null,
        ?string $documentRoot = null
    ): array {
        $checks = [];
        $add = static function (string $id, string $label, string $status, string $detail) use (&$checks): void {
            $checks[] = compact('id', 'label', 'status', 'detail');
        };

        $add(
            'php_version',
            'PHP 8.2 or newer',
            PHP_VERSION_ID >= 80200 ? 'VERIFIED' : 'BLOCKED',
            PHP_VERSION_ID >= 80200 ? 'Compatible PHP version is active.' : 'PHP 8.2 or newer is required.'
        );

        foreach (self::REQUIRED_EXTENSIONS as $extension) {
            $loaded = $extensionState === null
                ? extension_loaded($extension)
                : (bool) ($extensionState[strtolower($extension)] ?? $extensionState[$extension] ?? false);
            $add(
                'extension_' . strtolower($extension),
                $extension . ' extension',
                $loaded ? 'VERIFIED' : 'BLOCKED',
                $loaded ? 'Required runtime extension is loaded.' : 'Required runtime extension is unavailable.'
            );
        }

        $iniValues ??= [];
        foreach (['upload_max_filesize', 'post_max_size', 'memory_limit', 'max_execution_time'] as $key) {
            $value = array_key_exists($key, $iniValues) ? (string) $iniValues[$key] : (string) ini_get($key);
            $add(
                'ini_' . $key,
                $key,
                $value !== '' ? 'VERIFIED' : 'HOSTING-DEPENDENT',
                $value !== '' ? 'PHP reports a configured value: ' . $value . '.' : 'Confirm this PHP limit in the hosting control panel.'
            );
        }

        $modules = function_exists('apache_get_modules') ? apache_get_modules() : null;
        if (is_array($modules)) {
            $rewrite = in_array('mod_rewrite', $modules, true);
            $add('mod_rewrite', 'Apache rewrite module', $rewrite ? 'VERIFIED' : 'BLOCKED', $rewrite ? 'mod_rewrite is loaded.' : 'Required front-controller rewriting is unavailable.');
        } else {
            $add('mod_rewrite', 'Apache rewrite module', 'HOSTING-DEPENDENT', 'Verify rewrite support with a deployed front-controller request.');
        }
        $add('htaccess', '.htaccess overrides', 'HOSTING-DEPENDENT', 'Verify access controls and rewrite rules on the deployed host.');

        $documentRoot ??= (string) ($server['DOCUMENT_ROOT'] ?? '');
        if ($documentRoot === '') {
            $add('document_root', 'Public document root', 'HOSTING-DEPENDENT', 'No hosted document root is available in this CLI context.');
        } else {
            $expected = realpath(BASE_PATH . '/public');
            $actual = realpath($documentRoot);
            $safe = $expected !== false && $actual !== false && strcasecmp($expected, $actual) === 0;
            $protectedRoot = DocumentStorage::protectionMode() === DocumentStorage::PROTECTED_IN_WEBROOT
                && $actual !== false
                && strcasecmp((string) realpath(BASE_PATH), $actual) === 0
                && DocumentStorage::hasStaticWebDenialControls();
            $liveVerified = env_bool('WEBROOT_DENIAL_VERIFIED', false);
            $status = $safe || ($protectedRoot && $liveVerified) ? 'VERIFIED' : 'HOSTING-DEPENDENT';
            $detail = $safe
                ? 'The document root resolves to public/.'
                : ($protectedRoot
                    ? ($liveVerified ? 'PROTECTED_IN_WEBROOT controls are recorded as live-verified.' : 'PROTECTED_IN_WEBROOT: PENDING LIVE VERIFICATION of every private path.')
                    : 'Confirm the documented provider-specific web-root layout before upload.');
            $add('document_root', 'Public document root', $status, $detail);
        }

        if ($server === []) {
            $add('https_indicator', 'Direct HTTPS indication', 'HOSTING-DEPENDENT', 'Verify the direct server HTTPS signal on the deployed origin.');
        } else {
            $https = TransportSecurity::isHttps($server);
            $add('https_indicator', 'Direct HTTPS indication', $https ? 'VERIFIED' : 'HOSTING-DEPENDENT', $https ? 'A trusted direct HTTPS indicator is present.' : 'No trusted direct HTTPS indication is present; do not trust arbitrary forwarded headers.');
        }

        foreach (['storage/logs', 'storage/sessions', 'storage/uploads'] as $directory) {
            $path = BASE_PATH . '/' . $directory;
            $writable = is_dir($path) && is_writable($path);
            $add('writable_' . str_replace('/', '_', $directory), $directory . ' writable', $writable ? 'VERIFIED' : 'BLOCKED', $writable ? 'Required private runtime directory is writable.' : 'Create the private directory with least necessary write access.');
        }

        $add('database_service', 'Hosted database service/account', 'HOSTING-DEPENDENT', 'Confirm the authorized production host, database, port, and restricted runtime account without exposing values.');
        $add('certificate_redirect', 'Certificate and canonical redirect', 'HOSTING-DEPENDENT', 'Validate the certificate and HTTP-to-HTTPS behavior against the authorized origin.');
        $add('log_access', 'Private log access and retention', 'HOSTING-DEPENDENT', 'Confirm private log location, access controls, and retention in the hosting panel.');
        $add('rate_limit', 'Infrastructure rate limiting', 'HOSTING-DEPENDENT', 'Confirm provider controls; no external rate-limit infrastructure is assumed.');

        $counts = ['verified' => 0, 'hosting_dependent' => 0, 'blocked' => 0, 'not_applicable' => 0];
        foreach ($checks as $check) {
            $key = strtolower(str_replace('-', '_', $check['status']));
            $counts[$key]++;
        }

        return [
            'status' => $counts['blocked'] > 0 ? 'BLOCKED' : ($counts['hosting_dependent'] > 0 ? 'HOSTING-DEPENDENT' : 'VERIFIED'),
            'summary' => $counts,
            'checks' => $checks,
        ];
    }
}
