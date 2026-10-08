<?php
declare(strict_types=1);
namespace App\Models;
use App\Core\Database;

final class Honeytoken
{
    public static function findActiveByMaterial(string $material): ?array
    {
        if (!preg_match('/\ACHM_HONEY_[A-Z0-9_]{4,96}\z/D', $material)) {
            return null;
        }
        $statement = Database::connection()->prepare('SELECT id, token_identifier, description FROM honeytokens WHERE token_hash = :token_hash AND is_active = 1 LIMIT 1');
        $statement->execute(['token_hash' => hash('sha256', $material)]);
        $row = $statement->fetch();
        return is_array($row) ? $row : null;
    }

    public static function allSafe(): array
    {
        return Database::connection()->query('SELECT id, token_identifier, description, is_active, triggered_at, created_at FROM honeytokens ORDER BY id')->fetchAll();
    }

    public static function recentEvents(int $limit = 30): array
    {
        $statement = Database::connection()->prepare('SELECT he.id, he.created_at, h.token_identifier, se.event_type, se.endpoint FROM honeytoken_events he JOIN honeytokens h ON h.id = he.honeytoken_id JOIN security_events se ON se.id = he.security_event_id ORDER BY he.created_at DESC, he.id DESC LIMIT :limit');
        $statement->bindValue('limit', min(max($limit, 1), 100), \PDO::PARAM_INT);
        $statement->execute();
        return $statement->fetchAll();
    }
}
