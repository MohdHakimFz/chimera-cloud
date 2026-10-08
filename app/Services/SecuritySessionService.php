<?php
declare(strict_types=1);
namespace App\Services;
use App\Core\Database;
use PDO;
use Throwable;

final class SecuritySessionService
{
    public const WINDOW_MINUTES = 30;

    public static function correlate(int $eventId): ?int
    {
        $database = Database::connection();
        $database->beginTransaction();
        try {
            $eventStatement = $database->prepare('SELECT id, security_session_id, event_type, source_safe_identifier, user_agent_summary, metadata_json FROM security_events WHERE id = :id FOR UPDATE');
            $eventStatement->execute(['id'=>$eventId]);
            $event = $eventStatement->fetch();
            if (!is_array($event)) { $database->rollBack(); return null; }
            if ($event['security_session_id'] !== null) { $database->commit(); return (int)$event['security_session_id']; }
            $source = (string)($event['source_safe_identifier'] ?? '');
            if ($source === '') { $database->commit(); return null; }
            $metadata = json_decode((string)($event['metadata_json'] ?? ''), true) ?: [];
            $actorId = isset($metadata['actor_user_id']) && is_numeric($metadata['actor_user_id']) ? (int)$metadata['actor_user_id'] : null;
            $session = self::findActive($database, $source, $actorId);
            if ($session === null) $session = self::create($database, $source, $actorId, (string)($event['user_agent_summary'] ?? ''));
            $sessionId = (int)$session['id'];
            $effectiveWeight = self::effectiveWeight($database, $sessionId, (string) $event['event_type'], $metadata);
            $score = ThreatScoringService::apply($database, $sessionId, $eventId, (string)$event['event_type'], (int)$session['threat_score'], $effectiveWeight);
            $classification = ThreatScoringService::classification($score);
            $updateSession = $database->prepare('UPDATE security_sessions SET threat_score = :score, classification = :classification, request_count = request_count + 1, last_seen_at = CURRENT_TIMESTAMP WHERE id = :id');
            $updateSession->execute(['score'=>$score,'classification'=>$classification,'id'=>$sessionId]);
            $updateEvent = $database->prepare('UPDATE security_events SET security_session_id = :session_id, risk_delta = :risk_delta WHERE id = :event_id AND security_session_id IS NULL');
            $updateEvent->execute(['session_id'=>$sessionId,'risk_delta'=>$effectiveWeight,'event_id'=>$eventId]);
            if ($updateEvent->rowCount() !== 1) throw new \RuntimeException('Security event correlation changed concurrently.');
            $database->commit();
            return $sessionId;
        } catch (Throwable $exception) {
            if ($database->inTransaction()) $database->rollBack();
            throw $exception;
        }
    }

    private static function findActive(PDO $database, string $source, ?int $actorId): ?array
    {
        $sql = 'SELECT id, threat_score FROM security_sessions WHERE source_hash = :source_hash AND last_seen_at >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ' . self::WINDOW_MINUTES . ' MINUTE) AND ' . ($actorId === null ? 'user_id IS NULL' : 'user_id = :user_id') . ' ORDER BY last_seen_at DESC, id DESC LIMIT 1 FOR UPDATE';
        $statement=$database->prepare($sql);$parameters=['source_hash'=>$source];if($actorId!==null)$parameters['user_id']=$actorId;$statement->execute($parameters);$row=$statement->fetch();return is_array($row)?$row:null;
    }

    private static function create(PDO $database, string $source, ?int $actorId, string $userAgent): array
    {
        $identifier=sprintf('%s-%s-%s-%s-%s',bin2hex(random_bytes(4)),bin2hex(random_bytes(2)),'4'.substr(bin2hex(random_bytes(2)),1),dechex((hexdec(substr(bin2hex(random_bytes(2)),0,1))&3)|8).substr(bin2hex(random_bytes(2)),1),bin2hex(random_bytes(6)));
        $statement=$database->prepare('INSERT INTO security_sessions (session_identifier,user_id,source_hash,user_agent_hash,threat_score,classification,request_count) VALUES (:identifier,:user_id,:source_hash,:user_agent_hash,0,\'LOW\',0)');
        $statement->execute(['identifier'=>$identifier,'user_id'=>$actorId,'source_hash'=>$source,'user_agent_hash'=>$userAgent===''?null:hash('sha256',$userAgent)]);
        return ['id'=>(int)$database->lastInsertId(),'threat_score'=>0];
    }

    private static function effectiveWeight(PDO $database, int $sessionId, string $eventType, array $metadata): int
    {
        $weight = ThreatScoringService::weight($eventType);
        if ($eventType !== 'DECOY_ACCESSED' || $weight === 0) {
            return $weight;
        }
        $decoyIdentifier = (string) ($metadata['target_identifier'] ?? $metadata['decoy_identifier'] ?? '');
        if ($decoyIdentifier === '') {
            return $weight;
        }
        $statement = $database->prepare(
            "SELECT COUNT(*) FROM security_events
             WHERE security_session_id = :session_id
               AND event_type = 'DECOY_ACCESSED'
               AND JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.target_identifier')) = :decoy_identifier"
        );
        $statement->execute(['session_id' => $sessionId, 'decoy_identifier' => $decoyIdentifier]);
        return (int) $statement->fetchColumn() > 0 ? 0 : $weight;
    }
}
