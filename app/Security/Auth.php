<?php

declare(strict_types=1);

namespace App\Security;

use App\Core\Session;
use App\Models\User;

final class Auth
{
    private static ?array $resolvedUser = null;
    private static bool $resolved = false;

    public static function attempt(string $email, string $password): bool
    {
        $account = User::findByEmail($email);
        if ($account === null || !$account['is_active'] || !password_verify($password, $account['password_hash'])) {
            password_verify($password, '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');
            return false;
        }

        User::recordLogin((int) $account['id']);
        Session::regenerate();
        Session::put('user_id', (int) $account['id']);
        Session::put('authenticated_at', time());
        self::$resolvedUser = User::safe($account);
        self::$resolved = true;
        return true;
    }

    public static function login(array $account): void
    {
        Session::regenerate();
        Session::put('user_id', (int) $account['id']);
        Session::put('authenticated_at', time());
        self::$resolvedUser = User::safe($account);
        self::$resolved = true;
    }

    public static function logout(): void
    {
        self::$resolvedUser = null;
        self::$resolved = true;
        Session::invalidate();
    }

    public static function user(): ?array
    {
        if (self::$resolved) {
            return self::$resolvedUser;
        }
        self::$resolved = true;
        $id = Session::get('user_id');
        self::$resolvedUser = is_numeric($id) ? User::findById((int) $id) : null;
        if (self::$resolvedUser !== null) {
            self::$resolvedUser = User::safe(self::$resolvedUser);
        }
        return self::$resolvedUser;
    }

    public static function check(): bool
    {
        return self::user() !== null;
    }

    public static function hasAnyRole(array $roles): bool
    {
        $account = self::user();
        return $account !== null && in_array($account['role'], $roles, true);
    }
}
