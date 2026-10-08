<?php

declare(strict_types=1);

namespace App\Services;

use App\Core\Database;
use App\Core\Request;
use App\Security\SecurityEventTaxonomy;
use Throwable;

final class SecurityEventService
{
    private const FORBIDDEN_KEYS = ['password', 'passwd', 'secret', 'token', 'csrf', 'cookie', 'authorization', 'session', 'credential', 'content', 'path', 'storage', 'email', 'name', 'source_ip'];

    public static function record(Request $request, string $eventType, ?int $actorUserId = null, array $context = []): ?int
    {
        try {
            $definition = SecurityEventTaxonomy::definition($eventType);
            $metadata = self::safeMetadata($context['metadata'] ?? []);
            $statement = Database::connection()->prepare(
                'INSERT INTO security_events
                 (security_session_id, event_type, source_safe_identifier, endpoint, http_method,
                  user_agent_summary, severity, risk_delta, description, metadata_json)
                 VALUES
                 (NULL, :event_type, :source_safe_identifier, :endpoint, :http_method,
                  :user_agent_summary, :severity, 0, :description, :metadata_json)'
            );
            $metadata = array_merge([
                'category' => $definition['category'],
                'outcome' => $definition['outcome'],
                'actor_user_id' => $actorUserId,
                'target_type' => self::nullableIdentifier($context['target_type'] ?? null, 64),
                'target_identifier' => self::nullableIdentifier($context['target_identifier'] ?? null, 128),
            ], $metadata);
            $metadata = array_filter($metadata, static fn (mixed $value): bool => $value !== null && $value !== '');
            $sourceIdentifier = self::safeSourceIdentifier($request);
            $statement->execute([
                'event_type' => $eventType,
                'source_safe_identifier' => $sourceIdentifier,
                'endpoint' => self::text($request->path(), 255),
                'http_method' => preg_match('/\A[A-Z]{1,10}\z/', $request->method()) ? $request->method() : 'UNKNOWN',
                'user_agent_summary' => self::userAgent($request),
                'severity' => $definition['severity'],
                'description' => $definition['description'],
                'metadata_json' => $metadata === [] ? null : json_encode($metadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            ]);
            $eventId = (int) Database::connection()->lastInsertId();
            if ($definition['category'] !== 'LAB') {
                try {
                    SecuritySessionService::correlate($eventId);
                } catch (Throwable) {
                    error_log('CHIMERA security-session assessment failed for event ' . $eventId . '.');
                }
            }
            return $eventId;
        } catch (Throwable $exception) {
            error_log('CHIMERA telemetry write failed for event type ' . preg_replace('/[^A-Z_]/', '', $eventType));
            return null;
        }
    }

    public static function safeMetadata(array $metadata): array
    {
        $safe = [];
        foreach ($metadata as $key => $value) {
            $key = strtolower((string) $key);
            if (!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/', $key) || self::forbiddenKey($key)) {
                continue;
            }
            if (is_bool($value) || is_int($value) || is_float($value)) {
                $safe[$key] = $value;
            } elseif (is_string($value)) {
                $safe[$key] = self::text($value, 200);
            } elseif (is_array($value)) {
                $items = array_slice(array_values(array_filter(array_map(
                    static fn (mixed $item): ?string => is_scalar($item) ? self::text((string) $item, 80) : null,
                    $value
                ))), 0, 10);
                if ($items !== []) {
                    $safe[$key] = $items;
                }
            }
        }
        return $safe;
    }

    public static function safeSourceIdentifier(Request $request): ?string
    {
        $sourceIp = self::sourceIp($request);
        if ($sourceIp === null) {
            return null;
        }
        $hashKey = (string) env('TELEMETRY_HASH_KEY', '');
        return $hashKey === '' ? hash('sha256', $sourceIp) : hash_hmac('sha256', $sourceIp, $hashKey);
    }

    private static function forbiddenKey(string $key): bool
    {
        foreach (self::FORBIDDEN_KEYS as $forbidden) {
            if (str_contains($key, $forbidden)) {
                return true;
            }
        }
        return false;
    }

    private static function sourceIp(Request $request): ?string
    {
        $candidate = trim((string) $request->server('REMOTE_ADDR', ''));
        return filter_var($candidate, FILTER_VALIDATE_IP) !== false ? $candidate : null;
    }

    private static function userAgent(Request $request): ?string
    {
        $agent = trim((string) $request->server('HTTP_USER_AGENT', ''));
        return $agent === '' ? null : self::text($agent, 255);
    }

    private static function nullableIdentifier(mixed $value, int $limit): ?string
    {
        if (!is_scalar($value)) {
            return null;
        }
        $value = trim((string) $value);
        return $value === '' ? null : self::text($value, $limit);
    }

    private static function text(string $value, int $limit): string
    {
        $value = preg_replace('/[\x00-\x1F\x7F]/u', '', $value) ?? '';
        return mb_substr($value, 0, $limit);
    }
}
