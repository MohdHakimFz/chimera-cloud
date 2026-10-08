<?php
declare(strict_types=1);
namespace App\Services;
use App\Core\Request;
use App\Models\DecoyEndpoint;
use App\Security\Auth;

final class DecoyService
{
    public static function resolve(Request $request): ?array
    {
        $decoy = DecoyEndpoint::findActiveByPath($request->path());
        if ($decoy === null) return null;
        $actor = Auth::user();
        $actorId = $actor === null ? null : (int) $actor['id'];
        $adaptive = AdaptiveDeceptionService::select($request, $actorId);
        SecurityEventService::record($request, 'DECOY_ACCESSED', $actor === null ? null : (int) $actor['id'], [
            'target_type' => 'decoy', 'target_identifier' => $decoy['decoy_identifier'],
            'metadata' => [
                'decoy_identifier' => $decoy['decoy_identifier'],
                'response_mode' => $decoy['response_mode'],
                'interaction_type' => 'route_access',
                'deception_profile' => $adaptive['profile']['name'],
                'response_variant' => $adaptive['profile']['variant'],
            ],
        ]);
        AdaptiveDeceptionService::recordDecision($request, $actorId, $decoy, $adaptive);
        $decoy['adaptive'] = $adaptive;
        return $decoy;
    }
}
