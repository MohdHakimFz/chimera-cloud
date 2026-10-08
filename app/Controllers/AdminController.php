<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Models\User;
use App\Models\Activity;
use App\Models\Document;

final class AdminController
{
    public function index(Request $request): never
    {
        Response::view('admin/index', [
            'title' => 'Administration',
            'counts' => User::countsByRole(),
            'recentUsers' => User::recent(),
            'documentSummary' => Document::applicationSummary(),
            'recentDocuments' => Document::recentForAdmin(),
            'recentActivity' => Activity::recentForAdmin(),
        ]);
    }
}
