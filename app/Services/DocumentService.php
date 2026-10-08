<?php

declare(strict_types=1);

namespace App\Services;

use App\Core\Database;
use App\Models\Activity;
use App\Models\Document;
use App\Security\UploadValidator;
use RuntimeException;
use Throwable;

final class DocumentService
{
    public static function upload(int $userId, array $file): array
    {
        $maxBytes = (int) env('DOCUMENT_MAX_BYTES', 5242880);
        $allowed = array_values(array_filter(array_map(
            static fn (string $extension): string => strtolower(trim($extension)),
            explode(',', (string) env('DOCUMENT_ALLOWED_EXTENSIONS', 'pdf,txt,csv,md'))
        )));
        $validated = UploadValidator::validate($file, $maxBytes, $allowed);
        if ($validated['errors'] !== []) {
            return $validated;
        }

        if (!is_uploaded_file($validated['temporary_path'])) {
            $validated['errors']['document'] = 'The file was not received through a valid HTTP upload.';
            return $validated;
        }

        DocumentStorage::ensureDirectories();
        do {
            $storageName = UploadValidator::generateStorageName($validated['extension']);
            $destination = DocumentStorage::path($storageName);
        } while (file_exists($destination));

        if (!move_uploaded_file($validated['temporary_path'], $destination)) {
            throw new RuntimeException('The uploaded document could not be stored.');
        }
        @chmod($destination, 0640);

        $checksum = hash_file('sha256', $destination);
        if (!is_string($checksum)) {
            @unlink($destination);
            throw new RuntimeException('The uploaded document could not be verified.');
        }

        $database = Database::connection();
        $database->beginTransaction();
        try {
            $statement = $database->prepare(
                'INSERT INTO documents (user_id, original_name, storage_name, mime_type, size_bytes, checksum_sha256)
                 VALUES (:user_id, :original_name, :storage_name, :mime_type, :size_bytes, :checksum_sha256)'
            );
            $statement->execute([
                'user_id' => $userId,
                'original_name' => $validated['original_name'],
                'storage_name' => $storageName,
                'mime_type' => $validated['mime_type'],
                'size_bytes' => $validated['size_bytes'],
                'checksum_sha256' => $checksum,
            ]);
            $id = (int) $database->lastInsertId();
            Activity::record($userId, 'DOCUMENT_UPLOADED', 'Document uploaded.', [
                'document_id' => $id,
                'original_name' => $validated['original_name'],
                'size_bytes' => $validated['size_bytes'],
            ]);
            $database->commit();
            return ['errors' => [], 'document_id' => $id];
        } catch (Throwable $exception) {
            if ($database->inTransaction()) {
                $database->rollBack();
            }
            @unlink($destination);
            throw $exception;
        }
    }

    public static function downloadable(array $document): string
    {
        $path = DocumentStorage::path((string) $document['storage_name']);
        if (is_link($path) || !is_file($path) || !is_readable($path)) {
            throw new RuntimeException('Document file is unavailable.');
        }

        $size = filesize($path);
        if ($size === false || (int) $size !== (int) $document['size_bytes']) {
            throw new RuntimeException('Document file integrity check failed.');
        }
        $checksum = hash_file('sha256', $path);
        if (!is_string($checksum) || !hash_equals((string) $document['checksum_sha256'], $checksum)) {
            throw new RuntimeException('Document checksum verification failed.');
        }
        return $path;
    }

    public static function deleteOwned(array $document, int $userId): void
    {
        DocumentStorage::ensureDirectories();
        $path = DocumentStorage::path((string) $document['storage_name']);
        $quarantine = null;
        $fileMissing = !is_file($path);

        if (!$fileMissing) {
            $quarantine = DocumentStorage::trashPath((string) $document['storage_name']);
            if (!rename($path, $quarantine)) {
                throw new RuntimeException('The document could not be prepared for deletion.');
            }
        }

        $database = Database::connection();
        $database->beginTransaction();
        try {
            $statement = $database->prepare('DELETE FROM documents WHERE id = :id AND user_id = :user_id');
            $statement->execute(['id' => $document['id'], 'user_id' => $userId]);
            if ($statement->rowCount() !== 1) {
                throw new RuntimeException('Document ownership changed before deletion.');
            }
            Activity::record($userId, 'DOCUMENT_DELETED', 'Document deleted.', [
                'document_id' => (int) $document['id'],
                'original_name' => (string) $document['original_name'],
                'file_missing' => $fileMissing,
            ]);
            $database->commit();
        } catch (Throwable $exception) {
            if ($database->inTransaction()) {
                $database->rollBack();
            }
            if ($quarantine !== null && is_file($quarantine) && !rename($quarantine, $path)) {
                error_log('CHIMERA document rollback could not restore quarantined file: ' . $document['storage_name']);
            }
            throw $exception;
        }

        if ($quarantine !== null && is_file($quarantine) && !unlink($quarantine)) {
            error_log('CHIMERA document trash cleanup failed: ' . basename($quarantine));
        }
    }
}
