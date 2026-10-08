<?php

declare(strict_types=1);

namespace App\Middleware;

use App\Core\Request;
use App\Core\Response;
use App\Security\Csrf;
use App\Security\Auth;
use App\Services\SecurityEventService;

final class VerifyCsrf implements Middleware
{
    public function handle(Request $request, callable $next): void
    {
        $submittedToken = $request->input('_token');
        if (!is_string($submittedToken) || !Csrf::valid($submittedToken)) {
            $account = Auth::user();
            SecurityEventService::record($request, 'CSRF_REJECTED', $account === null ? null : (int) $account['id']);
            Response::abort(419, 'Your form session expired. Refresh the page and try again.');
        }
        $next($request);
    }
}
