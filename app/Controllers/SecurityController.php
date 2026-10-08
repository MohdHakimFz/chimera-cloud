<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Models\SecurityEvent;
use App\Security\SecurityEventTaxonomy;

final class SecurityController
{
    public function index(Request $request): never
    {
        $filters = SecurityEvent::filters([
            'type' => $request->query('type'),
            'severity' => $request->query('severity'),
            'outcome' => $request->query('outcome'),
            'date_from' => $request->query('date_from'),
        ]);
        Response::view('security/index', [
            'title' => 'Security Operations',
            'summary' => SecurityEvent::summary(),
            'events' => SecurityEvent::filtered($filters),
            'filters' => $filters,
            'eventTypes' => SecurityEventTaxonomy::eventTypes(),
            'severities' => SecurityEventTaxonomy::severities(),
        ]);
    }

    public function show(Request $request): never
    {
        $event = SecurityEvent::find((int) $request->route('id', 0));
        if ($event === null) {
            Response::abort(404, 'The requested security event could not be found.');
        }
        Response::view('security/show', ['title' => 'Security event', 'event' => $event]);
    }
}
