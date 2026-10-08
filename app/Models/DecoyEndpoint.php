<?php
declare(strict_types=1);
namespace App\Models;
use App\Core\Database;

final class DecoyEndpoint
{
    public static function findActiveByPath(string $path): ?array
    {
        $statement = Database::connection()->prepare('SELECT id, decoy_identifier, path, name, type, response_mode FROM decoy_endpoints WHERE path = :path AND is_active = 1 LIMIT 1');
        $statement->execute(['path' => $path]);
        $row = $statement->fetch();
        return is_array($row) ? $row : null;
    }

    public static function all(): array
    {
        return Database::connection()->query('SELECT id, decoy_identifier, path, name, type, is_active, response_mode, created_at, updated_at FROM decoy_endpoints ORDER BY id')->fetchAll();
    }
}
