<?php

declare(strict_types=1);

namespace App\Models;

use App\Core\Database;
use App\Security\SecurityEventTaxonomy;
use PDO;

final class SecurityEvent
{
    public static function summary(): array
    {
        $database = Database::connection();
        $totals = ['total' => (int) $database->query('SELECT COUNT(*) FROM security_events')->fetchColumn()];
        foreach (SecurityEventTaxonomy::severities() as $severity) {
            $totals['severity'][$severity] = 0;
        }
        foreach ($database->query('SELECT severity, COUNT(*) AS total FROM security_events GROUP BY severity')->fetchAll() as $row) {
            $totals['severity'][$row['severity']] = (int) $row['total'];
        }
        foreach (['LOGIN_FAILURE', 'ACCESS_DENIED', 'ROLE_ACCESS_DENIED', 'OWNERSHIP_ACCESS_DENIED', 'DOCUMENT_UPLOAD_REJECTED', 'DOCUMENT_INTEGRITY_FAILURE'] as $type) {
            $statement = $database->prepare('SELECT COUNT(*) FROM security_events WHERE event_type = :event_type');
            $statement->execute(['event_type' => $type]);
            $totals['type'][$type] = (int) $statement->fetchColumn();
        }
        $totals['by_category'] = $database->query("SELECT JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.category')) AS category, COUNT(*) AS total FROM security_events GROUP BY category ORDER BY total DESC")->fetchAll();
        return $totals;
    }

    public static function filtered(array $filters, int $limit = 50): array
    {
        [$where, $parameters] = self::where($filters);
        $statement = Database::connection()->prepare(
            "SELECT id, event_type, endpoint, http_method, user_agent_summary, severity, description, metadata_json, created_at,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.actor_user_id')) AS actor_user_id,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.category')) AS category,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.outcome')) AS outcome,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.target_type')) AS target_type,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.target_identifier')) AS target_identifier
             FROM security_events" . $where . ' ORDER BY created_at DESC, id DESC LIMIT :limit'
        );
        foreach ($parameters as $key => $value) {
            $statement->bindValue($key, $value);
        }
        $statement->bindValue('limit', min(max($limit, 1), 100), PDO::PARAM_INT);
        $statement->execute();
        return array_map([self::class, 'present'], $statement->fetchAll());
    }

    public static function find(int $id): ?array
    {
        $statement = Database::connection()->prepare(
            "SELECT id, event_type, endpoint, http_method, user_agent_summary, severity, description, metadata_json, created_at,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.actor_user_id')) AS actor_user_id,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.category')) AS category,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.outcome')) AS outcome,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.target_type')) AS target_type,
                    JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.target_identifier')) AS target_identifier
             FROM security_events WHERE id = :id LIMIT 1"
        );
        $statement->execute(['id' => $id]);
        $event = $statement->fetch();
        return is_array($event) ? self::present($event) : null;
    }

    public static function filters(array $query): array
    {
        $type = strtoupper(trim((string) ($query['type'] ?? '')));
        $severity = strtoupper(trim((string) ($query['severity'] ?? '')));
        $outcome = strtoupper(trim((string) ($query['outcome'] ?? '')));
        $dateFrom = trim((string) ($query['date_from'] ?? ''));
        return [
            'type' => in_array($type, SecurityEventTaxonomy::eventTypes(), true) ? $type : '',
            'severity' => in_array($severity, SecurityEventTaxonomy::severities(), true) ? $severity : '',
            'outcome' => in_array($outcome, ['SUCCESS', 'FAILURE', 'DENIED', 'REJECTED', 'ERROR'], true) ? $outcome : '',
            'date_from' => preg_match('/\A\d{4}-\d{2}-\d{2}\z/', $dateFrom) ? $dateFrom : '',
        ];
    }

    private static function where(array $filters): array
    {
        $clauses = [];
        $parameters = [];
        foreach (['type' => 'event_type', 'severity' => 'severity'] as $key => $column) {
            if (($filters[$key] ?? '') !== '') {
                $clauses[] = "{$column} = :{$key}";
                $parameters[$key] = $filters[$key];
            }
        }
        if (($filters['outcome'] ?? '') !== '') {
            $clauses[] = "JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.outcome')) = :outcome";
            $parameters['outcome'] = $filters['outcome'];
        }
        if (($filters['date_from'] ?? '') !== '') {
            $clauses[] = 'created_at >= :date_from';
            $parameters['date_from'] = $filters['date_from'] . ' 00:00:00';
        }
        return [$clauses === [] ? '' : ' WHERE ' . implode(' AND ', $clauses), $parameters];
    }

    private static function present(array $event): array
    {
        $event['id'] = (int) $event['id'];
        $event['actor_user_id'] = $event['actor_user_id'] === null || $event['actor_user_id'] === '' ? null : (int) $event['actor_user_id'];
        $event['metadata'] = $event['metadata_json'] === null ? [] : (json_decode((string) $event['metadata_json'], true) ?: []);
        unset(
            $event['metadata']['source_ip'],
            $event['metadata_json'],
            $event['source_ip'],
            $event['source_safe_identifier']
        );
        return $event;
    }
}
