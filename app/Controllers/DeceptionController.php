<?php
declare(strict_types=1);
namespace App\Controllers;
use App\Core\Request;
use App\Core\Response;
use App\Models\DecoyEndpoint;
use App\Models\Deception;
use App\Models\Honeytoken;

final class DeceptionController
{
    public function index(Request $request): never
    {
        Response::view('security/deception', ['title' => 'Cyber Deception', 'summary' => Deception::summary(), 'decoys' => DecoyEndpoint::all(), 'honeytokens' => Honeytoken::allSafe(), 'events' => Deception::recentEvents(), 'honeytokenEvents' => Honeytoken::recentEvents()]);
    }
}
