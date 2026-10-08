<?php
declare(strict_types=1);
namespace App\Models;
use App\Core\Database;

final class Deception
{
    public static function summary(): array
    {
        $database = Database::connection();
        return [
            'active_decoys' => (int) $database->query('SELECT COUNT(*) FROM decoy_endpoints WHERE is_active = 1')->fetchColumn(),
            'honeytokens' => (int) $database->query('SELECT COUNT(*) FROM honeytokens')->fetchColumn(),
            'decoy_interactions' => (int) $database->query("SELECT COUNT(*) FROM security_events WHERE event_type = 'DECOY_ACCESSED'")->fetchColumn(),
            'honeytoken_triggers' => (int) $database->query('SELECT COUNT(*) FROM honeytoken_events')->fetchColumn(),
            'top_decoys' => $database->query("SELECT JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.decoy_identifier')) AS decoy_identifier, COUNT(*) AS total FROM security_events WHERE event_type = 'DECOY_ACCESSED' GROUP BY decoy_identifier ORDER BY total DESC LIMIT 10")->fetchAll(),
        ];
    }

    public static function recentEvents(int $limit = 50): array
    {
        $statement = Database::connection()->prepare("SELECT id, event_type, endpoint, http_method, severity, description, metadata_json, created_at FROM security_events WHERE event_type IN ('DECOY_ACCESSED','HONEYTOKEN_TRIGGERED') ORDER BY created_at DESC, id DESC LIMIT :limit");
        $statement->bindValue('limit', min(max($limit, 1), 100), \PDO::PARAM_INT);
        $statement->execute();
        return array_map(static function (array $row): array {
            $row['metadata'] = json_decode((string) $row['metadata_json'], true) ?: [];
            unset($row['metadata']['source_ip'], $row['metadata_json'], $row['source_safe_identifier']);
            return $row;
        }, $statement->fetchAll());
    }
}
