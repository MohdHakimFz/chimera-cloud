<?php

declare(strict_types=1);

namespace App\Services;

use App\Core\Database;
use App\Core\Request;
use App\Models\AdaptiveDeception;
use App\Models\Honeytoken;
use Throwable;

final class AdaptiveDeceptionService
{
    private const ORDER = ['LOW' => 0, 'MEDIUM' => 1, 'HIGH' => 2, 'CRITICAL' => 3];

    private const PROFILES = [
        'LOW' => [
            'name' => 'LOW', 'variant' => 'minimal', 'metadata_richness' => 1,
            'breadcrumbs' => [], 'honeytoken_identifiers' => [],
        ],
        'MEDIUM' => [
            'name' => 'MEDIUM', 'variant' => 'contextual', 'metadata_richness' => 2,
            'breadcrumbs' => ['service-catalog', 'legacy-status'], 'honeytoken_identifiers' => [],
        ],
        'HIGH' => [
            'name' => 'HIGH', 'variant' => 'investigative', 'metadata_richness' => 3,
            'breadcrumbs' => ['service-catalog', 'legacy-status', 'backup-index'],
            'honeytoken_identifiers' => ['HT-API-001'],
        ],
        'CRITICAL' => [
            'name' => 'CRITICAL', 'variant' => 'immersive-safe', 'metadata_richness' => 4,
            'breadcrumbs' => ['service-catalog', 'legacy-status', 'backup-index', 'archive-manifest'],
            'honeytoken_identifiers' => ['HT-API-001', 'HT-BACKUP-001'],
        ],
    ];

    public static function policy(): array
    {
        return self::PROFILES;
    }

    public static function profileForLevel(string $threatLevel): array
    {
        return self::PROFILES[$threatLevel] ?? self::PROFILES['LOW'];
    }

    public static function select(Request $request, ?int $actorUserId): array
    {
        $fallback = self::fallback();
        try {
            $source = SecurityEventService::safeSourceIdentifier($request);
            if ($source === null) {
                return $fallback;
            }
            $parameters = ['source_hash' => $source];
            $actorClause = 'user_id IS NULL';
            if ($actorUserId !== null) {
                $actorClause = 'user_id = :user_id';
                $parameters['user_id'] = $actorUserId;
            }
            $statement = Database::connection()->prepare(
                'SELECT id, threat_score, classification FROM security_sessions
                 WHERE source_hash = :source_hash AND ' . $actorClause . '
                   AND last_seen_at >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ' . SecuritySessionService::WINDOW_MINUTES . ' MINUTE)
                 ORDER BY last_seen_at DESC, id DESC LIMIT 1'
            );
            $statement->execute($parameters);
            $session = $statement->fetch();
            if (!is_array($session)) {
                return $fallback;
            }
            $level = isset(self::PROFILES[$session['classification']]) ? (string) $session['classification'] : 'LOW';
            $previous = AdaptiveDeception::latestProfile((int) $session['id']);
            if ($previous !== null && self::ORDER[$previous] > self::ORDER[$level]) {
                $level = $previous;
            }
            return self::context($level, (int) $session['id'], (int) $session['threat_score'], (string) $session['classification'], $previous, false);
        } catch (Throwable) {
            error_log('CHIMERA adaptive deception selection failed; safe default used.');
            return $fallback;
        }
    }

    public static function recordDecision(Request $request, ?int $actorUserId, array $decoy, array $context): void
    {
        $metadata = [
            'selected_profile' => $context['profile']['name'],
            'previous_profile' => $context['previous_profile'] ?? 'NONE',
            'threat_level' => $context['threat_level'],
            'assessment_score' => $context['score'],
            'decoy_identifier' => $decoy['decoy_identifier'],
            'selection_reason' => $context['fallback'] ? 'safe_default' : 'active_session_assessment',
            'response_variant' => $context['profile']['variant'],
        ];
        if ($context['previous_profile'] === null) {
            SecurityEventService::record($request, 'DECEPTION_PROFILE_SELECTED', $actorUserId, ['target_type' => 'decoy_profile', 'target_identifier' => $context['profile']['name'], 'metadata' => $metadata]);
        } elseif ($context['previous_profile'] !== $context['profile']['name']) {
            SecurityEventService::record($request, 'DECEPTION_PROFILE_CHANGED', $actorUserId, ['target_type' => 'decoy_profile', 'target_identifier' => $context['profile']['name'], 'metadata' => $metadata]);
        }
        SecurityEventService::record($request, 'ADAPTIVE_DECOY_RENDERED', $actorUserId, ['target_type' => 'decoy', 'target_identifier' => $decoy['decoy_identifier'], 'metadata' => $metadata]);
    }

    public static function exposedHoneytokens(array $profile): array
    {
        try {
            $materials = [];
            foreach ($profile['honeytoken_identifiers'] ?? [] as $identifier) {
                $material = HoneytokenService::material((string) $identifier);
                if (Honeytoken::findActiveByMaterial($material) !== null) {
                    $materials[] = $material;
                }
            }
            return $materials;
        } catch (Throwable) {
            error_log('CHIMERA adaptive marker resolution failed; no markers exposed.');
            return [];
        }
    }

    private static function fallback(): array
    {
        return self::context('LOW', null, 0, 'LOW', null, true);
    }

    private static function context(string $level, ?int $sessionId, int $score, string $threatLevel, ?string $previous, bool $fallback): array
    {
        return [
            'profile' => self::PROFILES[$level],
            'security_session_id' => $sessionId,
            'score' => min(100, max(0, $score)),
            'threat_level' => $threatLevel,
            'previous_profile' => $previous,
            'fallback' => $fallback,
        ];
    }
}
