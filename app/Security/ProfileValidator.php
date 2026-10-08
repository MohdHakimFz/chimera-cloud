<?php

declare(strict_types=1);

namespace App\Security;

final class ProfileValidator
{
    public static function validateName(string $name): array
    {
        $name = trim(preg_replace('/\s+/u', ' ', $name) ?? '');
        $errors = [];
        if (mb_strlen($name) < 2 || mb_strlen($name) > 100) {
            $errors['name'] = 'Name must contain between 2 and 100 characters.';
        } elseif (preg_match('/[\x00-\x1F\x7F]/u', $name)) {
            $errors['name'] = 'Name contains unsupported control characters.';
        }

        return ['value' => $name, 'errors' => $errors];
    }
}
