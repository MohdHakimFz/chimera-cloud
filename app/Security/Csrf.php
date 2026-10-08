<?php

declare(strict_types=1);

namespace App\Security;

use App\Core\Session;

final class Csrf
{
    public static function token(): string
    {
        $token = Session::get('_csrf_token');
        if (!is_string($token) || strlen($token) < 32) {
            $token = bin2hex(random_bytes(32));
            Session::put('_csrf_token', $token);
        }
        return $token;
    }

    public static function valid(?string $token): bool
    {
        $stored = Session::get('_csrf_token');
        return is_string($token) && is_string($stored) && hash_equals($stored, $token);
    }
}

