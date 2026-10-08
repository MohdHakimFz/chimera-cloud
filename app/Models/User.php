<?php

declare(strict_types=1);

namespace App\Models;

use App\Core\Database;
use PDO;

final class User
{
    public static function findByEmail(string $email): ?array
    {
        $statement = Database::connection()->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
        $statement->execute(['email' => strtolower(trim($email))]);
        $user = $statement->fetch();
        return is_array($user) ? $user : null;
    }

    public static function findById(int $id): ?array
    {
        $statement = Database::connection()->prepare('SELECT * FROM users WHERE id = :id LIMIT 1');
        $statement->execute(['id' => $id]);
        $user = $statement->fetch();
        return is_array($user) && $user['is_active'] ? $user : null;
    }

    public static function create(string $name, string $email, string $password): array
    {
        $database = Database::connection();
        $database->beginTransaction();
        try {
            $statement = $database->prepare(
                'INSERT INTO users (name, email, password_hash, role, is_active) VALUES (:name, :email, :password_hash, :role, 1)'
            );
            $statement->execute([
                'name' => trim($name),
                'email' => strtolower(trim($email)),
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                'role' => 'user',
            ]);
            $id = (int) $database->lastInsertId();
            Activity::record($id, 'ACCOUNT_CREATED', 'Account created.');
            $database->commit();
            return self::findById($id) ?? [];
        } catch (\Throwable $exception) {
            if ($database->inTransaction()) {
                $database->rollBack();
            }
            throw $exception;
        }
    }

    public static function recordLogin(int $id): void
    {
        $database = Database::connection();
        $database->beginTransaction();
        try {
            $statement = $database->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
            $statement->execute(['id' => $id]);
            Activity::record($id, 'LOGIN', 'Signed in to CHIMERA CLOUD.');
            $database->commit();
        } catch (\Throwable $exception) {
            if ($database->inTransaction()) {
                $database->rollBack();
            }
            throw $exception;
        }
    }

    public static function updateName(int $id, string $name): void
    {
        $database = Database::connection();
        $database->beginTransaction();
        try {
            $statement = $database->prepare('UPDATE users SET name = :name WHERE id = :id AND is_active = 1');
            $statement->execute(['name' => $name, 'id' => $id]);
            if ($statement->rowCount() > 0) {
                Activity::record($id, 'PROFILE_UPDATED', 'Profile name updated.');
            }
            $database->commit();
        } catch (\Throwable $exception) {
            if ($database->inTransaction()) {
                $database->rollBack();
            }
            throw $exception;
        }
    }

    public static function countsByRole(): array
    {
        $statement = Database::connection()->query('SELECT role, COUNT(*) AS total FROM users GROUP BY role');
        $counts = ['user' => 0, 'admin' => 0, 'security_admin' => 0];
        foreach ($statement->fetchAll() as $row) {
            $counts[$row['role']] = (int) $row['total'];
        }
        return $counts;
    }

    public static function recent(int $limit = 8): array
    {
        $statement = Database::connection()->prepare('SELECT id, name, email, role, is_active, created_at FROM users ORDER BY created_at DESC LIMIT :limit');
        $statement->bindValue('limit', $limit, PDO::PARAM_INT);
        $statement->execute();
        return $statement->fetchAll();
    }

    public static function safe(array $user): array
    {
        unset($user['password_hash']);
        return $user;
    }
}
