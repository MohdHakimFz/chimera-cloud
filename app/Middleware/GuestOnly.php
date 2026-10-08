<?php

declare(strict_types=1);

namespace App\Middleware;

use App\Core\Request;
use App\Core\Response;
use App\Security\Auth;

final class GuestOnly implements Middleware
{
    public function handle(Request $request, callable $next): void
    {
        if (Auth::check()) {
            Response::redirect('/dashboard');
        }
        $next($request);
    }
}

