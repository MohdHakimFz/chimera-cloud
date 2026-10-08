<?php

declare(strict_types=1);

namespace App\Middleware;

use App\Core\Request;
use App\Core\Response;
use App\Core\Session;
use App\Security\Auth;
use App\Services\SecurityEventService;

final class Authenticate implements Middleware
{
    public function handle(Request $request, callable $next): void
    {
        if (!Auth::check()) {
            SecurityEventService::record($request, 'ACCESS_DENIED', null, ['metadata' => ['reason' => 'authentication_required']]);
            if ($request->isApi()) {
                Response::json(['error' => ['code' => 'UNAUTHENTICATED', 'message' => 'Authentication is required.']], 401);
            }
            Session::flash('error', 'Please sign in to continue.');
            Response::redirect('/login');
        }
        $next($request);
    }
}
