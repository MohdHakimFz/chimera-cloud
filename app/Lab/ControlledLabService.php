<?php

declare(strict_types=1);

namespace App\Lab;

use App\Core\Database;
use Throwable;

final class ControlledLabService
{
    private const DEFINITIONS = [
        'CHIM-VULN-001' => ['category' => 'BOLA / IDOR', 'route' => '/lab/idor', 'testing_notes' => 'Use actor analyst-a and compare object LAB-1001 with LAB-2001.'],
        'CHIM-VULN-002' => ['category' => 'SQL Injection', 'route' => '/lab/sqli', 'testing_notes' => "Compare ARC-001 with the bounded payload ' OR '1'='1."],
        'CHIM-VULN-003' => ['category' => 'Reflected XSS', 'route' => '/lab/xss', 'testing_notes' => 'Use a harmless alert or DOM marker. The page runs in a CSP sandbox with an opaque origin.'],
    ];

    private const LAB_OBJECTS = [
        'LAB-1001' => ['id' => 'LAB-1001', 'owner' => 'analyst-a', 'title' => 'Northwind assessment notes', 'classification' => 'SYNTHETIC-INTERNAL'],
        'LAB-2001' => ['id' => 'LAB-2001', 'owner' => 'analyst-b', 'title' => 'Bluebird audit worksheet', 'classification' => 'SYNTHETIC-RESTRICTED'],
    ];

    public static function enabled(): bool
    {
        return env_bool('VULNERABILITY_LAB_ENABLED', false);
    }

    public static function definitions(): array
    {
        return self::DEFINITIONS;
    }

    public static function sqlSearch(string $input, string $state): array
    {
        $input = trim(mb_substr($input, 0, 80));
        if ($input === '' || !self::safeSqlLabGrammar($input)) {
            return [];
        }
        $derived = "(SELECT 701 AS lab_record_id, 'ARC-001' AS lab_code, 'Synthetic archive manifest' AS title, 'analyst-a' AS owner_alias, 'LAB-ONLY' AS classification
                    UNION ALL SELECT 702, 'ARC-002', 'Synthetic service inventory', 'analyst-b', 'LAB-ONLY'
                    UNION ALL SELECT 703, 'ARC-003', 'Synthetic recovery worksheet', 'analyst-c', 'LAB-ONLY') AS lab_records";
        try {
            if ($state === 'REMEDIATED') {
                $statement = Database::connection()->prepare("SELECT lab_record_id,lab_code,title,owner_alias,classification FROM {$derived} WHERE lab_code = :lab_code");
                $statement->execute(['lab_code' => $input]);
                return $statement->fetchAll();
            }
            $statement = Database::connection()->query("SELECT lab_record_id,lab_code,title,owner_alias,classification FROM {$derived} WHERE lab_code = '{$input}'");
            return $statement->fetchAll();
        } catch (Throwable) {
            return [];
        }
    }

    public static function idorLookup(string $actor, string $objectId, string $state): ?array
    {
        $actor = strtolower(trim($actor));
        $objectId = strtoupper(trim($objectId));
        if (!in_array($actor, ['analyst-a', 'analyst-b'], true) || !preg_match('/\ALAB-[12]001\z/D', $objectId)) {
            return null;
        }
        $object = self::LAB_OBJECTS[$objectId] ?? null;
        if ($object === null || ($state === 'REMEDIATED' && $object['owner'] !== $actor)) {
            return null;
        }
        return $object;
    }

    public static function reflectedInput(string $input): string
    {
        $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $input) ?? '';
        return mb_substr($input, 0, 240);
    }

    private static function safeSqlLabGrammar(string $input): bool
    {
        if (!preg_match("/\A[A-Za-z0-9_' =-]+\z/D", $input)) {
            return false;
        }
        $lower = strtolower($input);
        foreach (['select', 'union', 'insert', 'update', 'delete', 'drop', 'alter', 'create', 'grant', 'load', 'outfile', 'benchmark', 'sleep', 'information', 'schema', 'mysql', '--', '#', '/*', ';', '@'] as $blocked) {
            if (str_contains($lower, $blocked)) {
                return false;
            }
        }
        return true;
    }
}
