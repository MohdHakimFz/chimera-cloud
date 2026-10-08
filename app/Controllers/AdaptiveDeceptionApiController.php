<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Models\AdaptiveDeception;

final class AdaptiveDeceptionApiController
{
    public function summary(Request $request): never
    {
        Response::json(['data' => AdaptiveDeception::summary()]);
    }

    public function session(Request $request): never
    {
        $data = AdaptiveDeception::forSession((int) $request->route('id', 0));
        if ($data === null) {
            Response::json(['error' => ['code' => 'NOT_FOUND', 'message' => 'Resource not found.']], 404);
        }
        Response::json(['data' => $data]);
    }

    public function events(Request $request): never
    {
        $events = AdaptiveDeception::recentEvents(100);
        Response::json(['data' => $events, 'meta' => ['count' => count($events)]]);
    }
}
