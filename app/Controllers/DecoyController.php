<?php
declare(strict_types=1);
namespace App\Controllers;
use App\Core\Request;
use App\Core\Response;
use App\Services\AdaptiveDeceptionService;
use App\Services\DecoyService;
use App\Services\HoneytokenService;

final class DecoyController
{
    public function show(Request $request): never
    {
        $decoy = DecoyService::resolve($request);
        if ($decoy === null) {
            if ($request->isApi()) Response::json(['error' => ['code' => 'NOT_FOUND', 'message' => 'Resource not found.']], 404);
            Response::abort(404, 'The requested page could not be found.');
        }
        if ($decoy['response_mode'] === 'SYNTHETIC_JSON') {
            $profile = $decoy['adaptive']['profile'];
            $payload = ['service' => 'chimera-debug-proxy', 'environment' => 'staging', 'status' => 'restricted', 'build' => 'legacy-2024.11'];
            if ($profile['metadata_richness'] >= 2) {
                $payload['components'] = ['gateway' => 'degraded', 'archive' => 'read-only'];
            }
            if ($profile['metadata_richness'] >= 3) {
                $payload['references'] = $profile['breadcrumbs'];
            }
            $tokens = AdaptiveDeceptionService::exposedHoneytokens($profile);
            if ($tokens !== []) {
                $payload['diagnostic_markers'] = $tokens;
            }
            if ($profile['metadata_richness'] >= 4) {
                $payload['service_map'] = ['legacy-auth' => 'offline', 'backup-catalog' => 'restricted', 'audit-relay' => 'sink-only'];
            }
            Response::json($payload);
        }
        if ($decoy['response_mode'] === 'SYNTHETIC_LOGIN') {
            Response::standaloneView('decoys/internal', ['decoy' => $decoy, 'adaptive' => $decoy['adaptive'], 'honeytokens' => AdaptiveDeceptionService::exposedHoneytokens($decoy['adaptive']['profile'])]);
        }
        Response::standaloneView('decoys/legacy', ['decoy' => $decoy, 'adaptive' => $decoy['adaptive'], 'honeytokens' => AdaptiveDeceptionService::exposedHoneytokens($decoy['adaptive']['profile'])], 403);
    }

    public function honeytoken(Request $request): never
    {
        $valid = HoneytokenService::trigger($request, trim((string) $request->query('token', '')));
        if (!$valid) Response::json(['error' => ['code' => 'NOT_FOUND', 'message' => 'Resource not found.']], 404);
        Response::json(['error' => ['code' => 'CREDENTIAL_REVOKED', 'message' => 'This synthetic credential is inactive.']], 410);
    }
}
