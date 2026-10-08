<?php
declare(strict_types=1);
namespace App\Services;
use PDO;

final class ThreatScoringService
{
    private const RULES = [
        'LOGIN_FAILURE' => [5, 'Failed authentication attempt.'],
        'ACCESS_DENIED' => [3, 'Unauthenticated protected-resource access.'],
        'ROLE_ACCESS_DENIED' => [10, 'Attempted access outside the assigned role.'],
        'OWNERSHIP_ACCESS_DENIED' => [12, 'Attempted access outside the resource ownership boundary.'],
        'CSRF_REJECTED' => [12, 'State-changing request failed CSRF validation.'],
        'DOCUMENT_UPLOAD_REJECTED' => [5, 'Document upload failed security validation.'],
        'DOCUMENT_INTEGRITY_FAILURE' => [20, 'Stored document integrity verification failed.'],
        'DECOY_ACCESSED' => [20, 'Static synthetic decoy was accessed.'],
        'HONEYTOKEN_TRIGGERED' => [35, 'High-confidence synthetic honeytoken interaction.'],
        'SECURITY_RELEVANT_APPLICATION_ERROR' => [10, 'Security-relevant application operation failed.'],
    ];

    public static function weight(string $eventType): int { return self::RULES[$eventType][0] ?? 0; }
    public static function rationale(string $eventType): string { return self::RULES[$eventType][1] ?? 'Non-scoring observation.'; }
    public static function rules(): array { return self::RULES; }

    public static function classification(int $score): string
    {
        $score = self::bounded($score);
        return $score >= 75 ? 'CRITICAL' : ($score >= 45 ? 'HIGH' : ($score >= 20 ? 'MEDIUM' : 'LOW'));
    }

    public static function bounded(int $score): int { return min(100, max(0, $score)); }

    public static function apply(PDO $database, int $sessionId, int $eventId, string $eventType, int $currentScore, ?int $effectiveWeight = null): int
    {
        $weight = $effectiveWeight ?? self::weight($eventType);
        if ($weight <= 0) return self::bounded($currentScore);
        $score = self::bounded($currentScore + $weight);
        $statement = $database->prepare('INSERT INTO security_score_contributors (security_session_id, rule_code, label, risk_delta) VALUES (:session_id, :rule_code, :label, :risk_delta)');
        $statement->execute(['session_id'=>$sessionId,'rule_code'=>$eventType,'label'=>'Event #' . $eventId . ': ' . self::rationale($eventType),'risk_delta'=>$weight]);
        return $score;
    }
}
