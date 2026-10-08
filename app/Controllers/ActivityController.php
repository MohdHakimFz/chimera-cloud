<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Models\Activity;
use App\Security\Auth;

final class ActivityController
{
    public function index(Request $request): never
    {
        $account = Auth::user();
        Response::view('activity/index', [
            'title' => 'Activity',
            'activities' => Activity::recentForUser((int) $account['id'], 50),
        ]);
    }
}
