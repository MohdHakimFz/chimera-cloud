<?php

declare(strict_types=1);

namespace App\Models;

use App\Core\Database;
use PDO;

final class Activity
{
    public static function record(int $userId, string $type, string $description, array $metadata = []): void
    {
        $statement = Database::connection()->prepare(
            'INSERT INTO user_activity (user_id, activity_type, description, metadata_json) VALUES (:user_id, :activity_type, :description, :metadata_json)'
        );
        $statement->execute([
            'user_id' => $userId,
            'activity_type' => $type,
            'description' => $description,
            'metadata_json' => $metadata === [] ? null : json_encode($metadata, JSON_THROW_ON_ERROR),
        ]);
    }

    public static function recentForUser(int $userId, int $limit = 20): array
    {
        $statement = Database::connection()->prepare(
            'SELECT id, activity_type, description, metadata_json, created_at FROM user_activity WHERE user_id = :user_id ORDER BY created_at DESC, id DESC LIMIT :limit'
        );
        $statement->bindValue('user_id', $userId, PDO::PARAM_INT);
        $statement->bindValue('limit', $limit, PDO::PARAM_INT);
        $statement->execute();
        return $statement->fetchAll();
    }

    public static function recentForAdmin(int $limit = 12): array
    {
        $statement = Database::connection()->prepare(
            'SELECT a.id, a.activity_type, a.description, a.created_at, u.name AS user_name, u.email AS user_email
             FROM user_activity a LEFT JOIN users u ON u.id = a.user_id
             ORDER BY a.created_at DESC, a.id DESC LIMIT :limit'
        );
        $statement->bindValue('limit', $limit, PDO::PARAM_INT);
        $statement->execute();
        return $statement->fetchAll();
    }
}
