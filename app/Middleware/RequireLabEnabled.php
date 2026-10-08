<?php

declare(strict_types=1);

namespace App\Middleware;

use App\Core\Request;
use App\Core\Response;

final class RequireLabEnabled implements Middleware
{
    public function handle(Request $request, callable $next): void
    {
        if (!env_bool('VULNERABILITY_LAB_ENABLED', false)) {
            if ($request->isApi()) {
                Response::json(['error' => ['code' => 'NOT_FOUND', 'message' => 'Resource not found.']], 404);
            }
            Response::abort(404, 'The requested page could not be found.');
        }
        $next($request);
    }
}
