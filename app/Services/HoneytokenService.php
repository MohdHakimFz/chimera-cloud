<?php
declare(strict_types=1);
namespace App\Services;
use App\Core\Database;
use App\Core\Request;
use App\Models\Honeytoken;
use App\Security\Auth;
use Throwable;

final class HoneytokenService
{
    public static function material(string $identifier): string
    {
        return 'CHM_HONEY_' . str_replace('-', '_', strtoupper($identifier));
    }

    public static function trigger(Request $request, string $material): bool
    {
        $token = Honeytoken::findActiveByMaterial($material);
        if ($token === null) return false;
        $actor = Auth::user();
        $actorId = $actor === null ? null : (int) $actor['id'];
        $adaptive = AdaptiveDeceptionService::select($request, $actorId);
        $eventId = SecurityEventService::record($request, 'HONEYTOKEN_TRIGGERED', $actor === null ? null : (int) $actor['id'], [
            'target_type' => 'honeytoken', 'target_identifier' => $token['token_identifier'],
            'metadata' => [
                'honeytoken_identifier' => $token['token_identifier'],
                'interaction_type' => 'token_presented',
                'deception_profile' => $adaptive['profile']['name'],
                'threat_level' => $adaptive['threat_level'],
            ],
        ]);
        if ($eventId === null) return true;
        try {
            $database = Database::connection();
            $database->beginTransaction();
            $statement = $database->prepare('INSERT INTO honeytoken_events (honeytoken_id, security_event_id) VALUES (:honeytoken_id, :security_event_id)');
            $statement->execute(['honeytoken_id' => $token['id'], 'security_event_id' => $eventId]);
            $update = $database->prepare('UPDATE honeytokens SET triggered_at = CURRENT_TIMESTAMP WHERE id = :id');
            $update->execute(['id' => $token['id']]);
            $database->commit();
        } catch (Throwable $exception) {
            if (isset($database) && $database->inTransaction()) $database->rollBack();
            error_log('CHIMERA honeytoken event linkage failed.');
        }
        return true;
    }
}
