<?php

declare(strict_types=1);

namespace App\Models;

use App\Core\Database;
use PDO;

final class AdaptiveDeception
{
    private const EVENT_TYPES = ['DECEPTION_PROFILE_SELECTED', 'DECEPTION_PROFILE_CHANGED', 'ADAPTIVE_DECOY_RENDERED'];

    public static function latestProfile(int $securitySessionId): ?string
    {
        $statement = Database::connection()->prepare(
            "SELECT JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.selected_profile'))
             FROM security_events
             WHERE security_session_id = :session_id
               AND event_type = 'ADAPTIVE_DECOY_RENDERED'
             ORDER BY id DESC LIMIT 1"
        );
        $statement->execute(['session_id' => $securitySessionId]);
        $profile = $statement->fetchColumn();
        return is_string($profile) && in_array($profile, ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], true) ? $profile : null;
    }

    public static function summary(): array
    {
        $database = Database::connection();
        $byProfile = ['LOW' => 0, 'MEDIUM' => 0, 'HIGH' => 0, 'CRITICAL' => 0];
        $rows = $database->query(
            "SELECT JSON_UNQUOTE(JSON_EXTRACT(e.metadata_json, '$.selected_profile')) AS profile, COUNT(*) AS total
             FROM security_events e
             WHERE e.event_type = 'ADAPTIVE_DECOY_RENDERED'
               AND e.id = (
                   SELECT MAX(e2.id) FROM security_events e2
                   WHERE e2.security_session_id = e.security_session_id
                     AND e2.event_type = 'ADAPTIVE_DECOY_RENDERED'
               )
             GROUP BY profile"
        )->fetchAll();
        foreach ($rows as $row) {
            if (isset($byProfile[$row['profile']])) {
                $byProfile[$row['profile']] = (int) $row['total'];
            }
        }
        return [
            'sessions_by_profile' => $byProfile,
            'adaptive_renders' => self::countType('ADAPTIVE_DECOY_RENDERED'),
            'profile_transitions' => self::countType('DECEPTION_PROFILE_CHANGED'),
            'interactions_by_profile' => self::groupEventByProfile('DECOY_ACCESSED'),
            'honeytoken_triggers_by_profile' => self::groupEventByProfile('HONEYTOKEN_TRIGGERED'),
        ];
    }

    public static function recentEvents(int $limit = 50): array
    {
        $statement = Database::connection()->prepare(
            "SELECT id, security_session_id, event_type, endpoint, http_method, severity, risk_delta, metadata_json, created_at
             FROM security_events
             WHERE event_type IN ('DECEPTION_PROFILE_SELECTED','DECEPTION_PROFILE_CHANGED','ADAPTIVE_DECOY_RENDERED')
             ORDER BY id DESC LIMIT :limit"
        );
        $statement->bindValue('limit', min(max($limit, 1), 100), PDO::PARAM_INT);
        $statement->execute();
        return array_map([self::class, 'present'], $statement->fetchAll());
    }

    public static function forSession(int $securitySessionId): ?array
    {
        $session = SecuritySession::find($securitySessionId);
        if ($session === null) {
            return null;
        }
        $statement = Database::connection()->prepare(
            "SELECT id, security_session_id, event_type, endpoint, http_method, severity, risk_delta, metadata_json, created_at
             FROM security_events
             WHERE security_session_id = :session_id
               AND event_type IN ('DECEPTION_PROFILE_SELECTED','DECEPTION_PROFILE_CHANGED','ADAPTIVE_DECOY_RENDERED','DECOY_ACCESSED','HONEYTOKEN_TRIGGERED')
             ORDER BY id, created_at"
        );
        $statement->execute(['session_id' => $securitySessionId]);
        $events = array_map([self::class, 'present'], $statement->fetchAll());
        return [
            'security_session_id' => $securitySessionId,
            'score' => $session['threat_score'],
            'threat_level' => $session['classification'],
            'current_profile' => self::latestProfile($securitySessionId) ?? 'LOW',
            'events' => $events,
        ];
    }

    private static function countType(string $eventType): int
    {
        $statement = Database::connection()->prepare('SELECT COUNT(*) FROM security_events WHERE event_type = :event_type');
        $statement->execute(['event_type' => $eventType]);
        return (int) $statement->fetchColumn();
    }

    private static function groupEventByProfile(string $eventType): array
    {
        $statement = Database::connection()->prepare(
            "SELECT COALESCE(JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.deception_profile')), 'UNSPECIFIED') AS profile,
                    COUNT(*) AS total
             FROM security_events WHERE event_type = :event_type GROUP BY profile ORDER BY total DESC"
        );
        $statement->execute(['event_type' => $eventType]);
        return array_map(static fn (array $row): array => ['profile' => $row['profile'], 'total' => (int) $row['total']], $statement->fetchAll());
    }

    private static function present(array $event): array
    {
        $event['id'] = (int) $event['id'];
        $event['security_session_id'] = $event['security_session_id'] === null ? null : (int) $event['security_session_id'];
        $event['risk_delta'] = (int) $event['risk_delta'];
        $event['metadata'] = json_decode((string) $event['metadata_json'], true) ?: [];
        unset(
            $event['metadata']['source_ip'],
            $event['metadata']['source_safe_identifier'],
            $event['metadata_json'],
            $event['source_ip'],
            $event['source_safe_identifier']
        );
        return $event;
    }
}
