<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Models\AdaptiveDeception;
use App\Services\AdaptiveDeceptionService;

final class AdaptiveDeceptionController
{
    public function index(Request $request): never
    {
        Response::view('security/adaptive', [
            'title' => 'Adaptive Deception',
            'summary' => AdaptiveDeception::summary(),
            'events' => AdaptiveDeception::recentEvents(50),
            'policy' => AdaptiveDeceptionService::policy(),
        ]);
    }

    public function show(Request $request): never
    {
        $decision = AdaptiveDeception::forSession((int) $request->route('id', 0));
        if ($decision === null) {
            Response::abort(404, 'The requested security session could not be found.');
        }
        Response::view('security/adaptive-show', ['title' => 'Session Deception', 'decision' => $decision]);
    }
}
