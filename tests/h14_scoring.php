<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Security\SecurityEventTaxonomy;
use App\Services\ThreatScoringService;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};

$expectedRules = [
    'ACCESS_DENIED' => 3,
    'LOGIN_FAILURE' => 5,
    'DOCUMENT_UPLOAD_REJECTED' => 5,
    'ROLE_ACCESS_DENIED' => 10,
    'SECURITY_RELEVANT_APPLICATION_ERROR' => 10,
    'OWNERSHIP_ACCESS_DENIED' => 12,
    'CSRF_REJECTED' => 12,
    'DOCUMENT_INTEGRITY_FAILURE' => 20,
    'DECOY_ACCESSED' => 20,
    'HONEYTOKEN_TRIGGERED' => 35,
];

$implementedRules = ThreatScoringService::rules();
$implementedWeights = array_map(static fn (array $rule): int => (int) $rule[0], $implementedRules);
$expectedKeys = array_keys($expectedRules);
$implementedKeys = array_keys($implementedWeights);
sort($expectedKeys);
sort($implementedKeys);
$check($implementedKeys === $expectedKeys, 'Positive scoring rule set contains exactly the ten approved event types');

foreach ($expectedRules as $eventType => $weight) {
    $check(
        ThreatScoringService::weight($eventType) === $weight
        && ($implementedWeights[$eventType] ?? null) === $weight,
        "{$eventType} has locked weight {$weight}"
    );
}

$nonScoringTypes = array_values(array_diff(SecurityEventTaxonomy::eventTypes(), array_keys($expectedRules)));
$unexpectedPositive = array_values(array_filter(
    $nonScoringTypes,
    static fn (string $eventType): bool => ThreatScoringService::weight($eventType) > 0
));
$check($nonScoringTypes !== [] && $unexpectedPositive === [], 'Every taxonomy event outside the approved rule set resolves to zero weight');

$boundedCases = [-1 => 0, 0 => 0, 19 => 19, 20 => 20, 44 => 44, 45 => 45, 74 => 74, 75 => 75, 100 => 100, 101 => 100, 10000 => 100];
foreach ($boundedCases as $input => $expected) {
    $check(ThreatScoringService::bounded($input) === $expected, "Score {$input} is bounded to {$expected}");
}

$classificationCases = [-1 => 'LOW', 0 => 'LOW', 19 => 'LOW', 20 => 'MEDIUM', 44 => 'MEDIUM', 45 => 'HIGH', 74 => 'HIGH', 75 => 'CRITICAL', 100 => 'CRITICAL', 101 => 'CRITICAL'];
foreach ($classificationCases as $score => $classification) {
    $check(ThreatScoringService::classification($score) === $classification, "Score {$score} classifies as {$classification}");
}

$serviceSource = (string) file_get_contents($root . '/app/Services/ThreatScoringService.php');
$applicationImports = [];
preg_match_all('/^use\s+(App\\\\[^;]+);/m', $serviceSource, $applicationImports);
$check(
    ($applicationImports[1] ?? []) === [],
    'Scoring service has no application-authority, document, lab, adaptive, or response dependency'
);
$check(
    !preg_match('/\b(?:UPDATE|DELETE|INSERT\s+INTO)\s+(?:users|documents|vulnerability_modules|vulnerability_state_changes)\b/i', $serviceSource),
    'Scoring service contains no account, role, document, or vulnerability-state mutation query'
);
$check(
    !preg_match('/\b(?:block|suspend|disable_account|change_role|grant_role|redirect|abort)\b/i', $serviceSource),
    'Scoring service contains no automated blocking, suspension, role change, or response action'
);
$check(
    substr_count($serviceSource, 'INSERT INTO security_score_contributors') === 1
    && !preg_match('/\bUPDATE\s+security_score_contributors\b|\bDELETE\s+FROM\s+security_score_contributors\b/i', $serviceSource),
    'Scoring service mutation scope is limited to append-only contributor evidence'
);

echo PHP_EOL . "{$passed} H14 scoring checks passed, {$failed} failed." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
