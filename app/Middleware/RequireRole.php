<?php

declare(strict_types=1);

namespace App\Middleware;

use App\Core\Request;
use App\Core\Response;
use App\Security\Auth;
use App\Services\SecurityEventService;

final class RequireRole implements Middleware
{
    public function __construct(private readonly array $roles)
    {
    }

    public function handle(Request $request, callable $next): void
    {
        if (!Auth::check()) {
            SecurityEventService::record($request, 'ACCESS_DENIED', null, ['metadata' => ['reason' => 'authentication_required']]);
            if ($request->isApi()) {
                Response::json(['error' => ['code' => 'UNAUTHENTICATED', 'message' => 'Authentication is required.']], 401);
            }
            Response::redirect('/login');
        }

        if (!Auth::hasAnyRole($this->roles)) {
            $account = Auth::user();
            SecurityEventService::record($request, 'ROLE_ACCESS_DENIED', $account === null ? null : (int) $account['id'], [
                'target_type' => 'role_area',
                'metadata' => ['required_roles' => $this->roles, 'actor_role' => $account['role'] ?? 'unknown'],
            ]);
            if ($request->isApi()) {
                Response::json(['error' => ['code' => 'FORBIDDEN', 'message' => 'You do not have permission to access this resource.']], 403);
            }
            Response::abort(403, 'You do not have permission to view this area.');
        }

        $next($request);
    }
}
