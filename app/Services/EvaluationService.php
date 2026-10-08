<?php

declare(strict_types=1);

namespace App\Services;

use DateTimeImmutable;
use Throwable;

final class EvaluationService
{
    public static function evidenceId(string $prefix, int $id): string
    {
        return (preg_replace('/[^A-Z]/', '', strtoupper($prefix)) ?: 'EVD') . '-' . str_pad((string) max(0, $id), 8, '0', STR_PAD_LEFT);
    }

    public static function secondsBetween(?string $start, ?string $end): ?int
    {
        if ($start === null || $end === null || $start === '' || $end === '') {
            return null;
        }
        try {
            $seconds = (new DateTimeImmutable($end))->getTimestamp() - (new DateTimeImmutable($start))->getTimestamp();
            return $seconds >= 0 ? $seconds : null;
        } catch (Throwable) {
            return null;
        }
    }

    public static function median(array $values): ?float
    {
        $values = array_values(array_map('floatval', $values));
        if ($values === []) {
            return null;
        }
        sort($values, SORT_NUMERIC);
        $middle = intdiv(count($values), 2);
        return count($values) % 2 === 1 ? $values[$middle] : ($values[$middle - 1] + $values[$middle]) / 2;
    }

    public static function durationSummary(array $values): array
    {
        $values = array_values(array_filter($values, static fn (mixed $value): bool => is_int($value) || is_float($value)));
        return [
            'measurable_sessions' => count($values),
            'average_seconds' => $values === [] ? null : round(array_sum($values) / count($values), 2),
            'minimum_seconds' => $values === [] ? null : min($values),
            'maximum_seconds' => $values === [] ? null : max($values),
        ];
    }

    public static function contributorEventId(string $label): ?int
    {
        return preg_match('/\AEvent #(\d+):/', $label, $matches) === 1 ? (int) $matches[1] : null;
    }
}
