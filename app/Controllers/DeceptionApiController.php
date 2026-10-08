<?php
declare(strict_types=1);
namespace App\Controllers;
use App\Core\Request;
use App\Core\Response;
use App\Models\DecoyEndpoint;
use App\Models\Deception;
use App\Models\Honeytoken;

final class DeceptionApiController
{
    public function summary(Request $request): never { Response::json(['data' => Deception::summary()]); }
    public function decoys(Request $request): never { Response::json(['data' => DecoyEndpoint::all()]); }
    public function honeytokens(Request $request): never { Response::json(['data' => Honeytoken::allSafe()]); }
    public function events(Request $request): never { $events = Deception::recentEvents(100); Response::json(['data' => $events, 'meta' => ['count' => count($events)]]); }
}
