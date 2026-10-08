<?php

declare(strict_types=1);

namespace App\Security;

use finfo;

final class UploadValidator
{
    public const MIME_MAP = [
        'pdf' => ['application/pdf'],
        'txt' => ['text/plain'],
        'csv' => ['text/plain', 'text/csv', 'application/csv'],
        'md' => ['text/plain', 'text/markdown'],
    ];

    public static function validate(array $file, int $maxBytes, array $allowedExtensions): array
    {
        $errors = [];
        $error = (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE);
        if ($error !== UPLOAD_ERR_OK) {
            return ['errors' => ['document' => self::uploadError($error)]];
        }

        $temporaryPath = (string) ($file['tmp_name'] ?? '');
        $reportedSize = (int) ($file['size'] ?? 0);
        $actualSize = is_file($temporaryPath) ? filesize($temporaryPath) : false;
        if ($actualSize === false || $actualSize <= 0 || $reportedSize <= 0) {
            $errors['document'] = 'The uploaded file is empty or unavailable.';
        } elseif ($actualSize > $maxBytes || $reportedSize > $maxBytes) {
            $errors['document'] = 'The document exceeds the maximum allowed size of ' . format_bytes($maxBytes) . '.';
        }

        $originalName = self::safeOriginalName((string) ($file['name'] ?? 'document'));
        $baseName=(string)pathinfo($originalName,PATHINFO_FILENAME);
        if(preg_match('/(?:^|\.)(?:php[0-9]?|phtml|phar|cgi|pl|py|sh)(?:\.|$)/i',$originalName)===1||preg_match('/\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\z/i',$baseName)===1){
            $errors['document']='This filename is not allowed.';
        }
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if ($extension === '' || !in_array($extension, $allowedExtensions, true) || !isset(self::MIME_MAP[$extension])) {
            $errors['document'] = 'This file extension is not allowed.';
        }

        $mime = '';
        if ($temporaryPath !== '' && is_file($temporaryPath)) {
            $detector = new finfo(FILEINFO_MIME_TYPE);
            $mime = (string) $detector->file($temporaryPath);
        }
        if ($extension !== '' && isset(self::MIME_MAP[$extension]) && !in_array($mime, self::MIME_MAP[$extension], true)) {
            $errors['document'] = 'The detected file type does not match the approved document format.';
        }

        return [
            'errors' => $errors,
            'original_name' => $originalName,
            'extension' => $extension,
            'mime_type' => $mime,
            'size_bytes' => $actualSize === false ? 0 : (int) $actualSize,
            'temporary_path' => $temporaryPath,
        ];
    }

    public static function safeOriginalName(string $name): string
    {
        $name = str_replace('\\', '/', $name);
        $name = basename($name);
        $name = preg_replace('/[\x00-\x1F\x7F]/u', '', $name) ?? 'document';
        $name = trim($name, " .\t\n\r\0\x0B");
        if ($name === '') {
            $name = 'document';
        }
        return mb_substr($name, 0, 255);
    }

    public static function generateStorageName(string $extension): string
    {
        return bin2hex(random_bytes(24)) . '.' . strtolower($extension);
    }

    private static function uploadError(int $error): string
    {
        return match ($error) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'The document exceeds the server upload limit.',
            UPLOAD_ERR_PARTIAL => 'The document upload was interrupted. Try again.',
            UPLOAD_ERR_NO_FILE => 'Choose a document to upload.',
            default => 'The document could not be uploaded safely.',
        };
    }
}
