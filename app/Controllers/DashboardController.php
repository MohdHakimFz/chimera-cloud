<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Models\Activity;
use App\Models\Document;
use App\Security\Auth;

final class DashboardController
{
    public function index(Request $request): never
    {
        $account = Auth::user();
        $userId = (int) $account['id'];
        Response::view('dashboard/index', [
            'title' => 'Workspace',
            'summary' => Document::summaryForUser($userId),
            'recentDocuments' => Document::recentForUser($userId),
            'recentActivity' => Activity::recentForUser($userId, 6),
        ]);
    }
}
