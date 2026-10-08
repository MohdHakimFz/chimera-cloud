<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Models\SecurityEvent;

final class SecurityApiController
{
    public function events(Request $request): never
    {
        $filters = SecurityEvent::filters([
            'type' => $request->query('type'),
            'severity' => $request->query('severity'),
            'outcome' => $request->query('outcome'),
            'date_from' => $request->query('date_from'),
        ]);
        $events = SecurityEvent::filtered($filters, 100);
        Response::json(['data' => $events, 'meta' => ['count' => count($events), 'filters' => $filters]]);
    }

    public function event(Request $request): never
    {
        $event = SecurityEvent::find((int) $request->route('id', 0));
        if ($event === null) {
            Response::json(['error' => ['code' => 'NOT_FOUND', 'message' => 'Resource not found.']], 404);
        }
        Response::json(['data' => $event]);
    }

    public function summary(Request $request): never
    {
        Response::json(['data' => SecurityEvent::summary()]);
    }
}
