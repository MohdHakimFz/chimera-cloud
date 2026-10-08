<?php

declare(strict_types=1);

namespace App\Models;

use App\Core\Database;
use PDO;

final class Document
{
    public static function allForUser(int $userId): array
    {
        $statement = Database::connection()->prepare(
            'SELECT id, original_name, mime_type, size_bytes, checksum_sha256, created_at, updated_at FROM documents WHERE user_id = :user_id ORDER BY created_at DESC, id DESC'
        );
        $statement->execute(['user_id' => $userId]);
        return $statement->fetchAll();
    }

    public static function recentForUser(int $userId, int $limit = 5): array
    {
        $statement = Database::connection()->prepare(
            'SELECT id, original_name, mime_type, size_bytes, created_at FROM documents WHERE user_id = :user_id ORDER BY created_at DESC, id DESC LIMIT :limit'
        );
        $statement->bindValue('user_id', $userId, PDO::PARAM_INT);
        $statement->bindValue('limit', $limit, PDO::PARAM_INT);
        $statement->execute();
        return $statement->fetchAll();
    }

    public static function findOwned(int $documentId, int $userId): ?array
    {
        $statement = Database::connection()->prepare(
            'SELECT id, user_id, original_name, storage_name, mime_type, size_bytes, checksum_sha256, created_at, updated_at
             FROM documents WHERE id = :id AND user_id = :user_id LIMIT 1'
        );
        $statement->execute(['id' => $documentId, 'user_id' => $userId]);
        $document = $statement->fetch();
        return is_array($document) ? $document : null;
    }

    public static function summaryForUser(int $userId): array
    {
        $statement = Database::connection()->prepare('SELECT COUNT(*) AS document_count, COALESCE(SUM(size_bytes), 0) AS storage_bytes FROM documents WHERE user_id = :user_id');
        $statement->execute(['user_id' => $userId]);
        $summary = $statement->fetch();
        return ['document_count' => (int) $summary['document_count'], 'storage_bytes' => (int) $summary['storage_bytes']];
    }

    public static function applicationSummary(): array
    {
        $summary = Database::connection()->query('SELECT COUNT(*) AS document_count, COALESCE(SUM(size_bytes), 0) AS storage_bytes FROM documents')->fetch();
        return ['document_count' => (int) $summary['document_count'], 'storage_bytes' => (int) $summary['storage_bytes']];
    }

    public static function recentForAdmin(int $limit = 8): array
    {
        $statement = Database::connection()->prepare(
            'SELECT d.id, d.original_name, d.mime_type, d.size_bytes, d.created_at, u.name AS owner_name, u.email AS owner_email
             FROM documents d INNER JOIN users u ON u.id = d.user_id
             ORDER BY d.created_at DESC, d.id DESC LIMIT :limit'
        );
        $statement->bindValue('limit', $limit, PDO::PARAM_INT);
        $statement->execute();
        return $statement->fetchAll();
    }
}
