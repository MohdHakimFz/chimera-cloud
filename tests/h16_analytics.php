<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Services\EvidenceExportService;
use App\Services\SecurityAnalyticsService;
use App\Services\ThreatScoringService;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$source = static fn (string $path): string => (string) file_get_contents($root . '/' . $path);

$service = $source('app/Services/SecurityAnalyticsService.php');
$export = $source('app/Services/EvidenceExportService.php');
$api = $source('app/Controllers/SecurityAnalyticsApiController.php');
$controller = $source('app/Controllers/SecurityAnalyticsController.php');
$dashboard = $source('resources/views/security/analytics.php');
$sessionView = $source('resources/views/security/analytics-session.php');
$routes = $source('routes/web.php');
$labEnvironment = $source('.env.example');

$valid = SecurityAnalyticsService::filters(['date_from' => '2026-01-01', 'date_to' => '2026-12-31', 'severity' => 'MEDIUM']);
$check($valid['valid'] === true && $valid['errors'] === [] && $valid['severity'] === 'MEDIUM', 'Valid bounded analytics filters are accepted');
$invalid = SecurityAnalyticsService::filters(['severity' => 'ROOT']);
$check($invalid['valid'] === false && $invalid['errors'] !== [] && $invalid['severity'] === '', 'Invalid allowlist values fail closed');
$fromOnly = SecurityAnalyticsService::filters(['date_from' => '2026-01-01']);
$toOnly = SecurityAnalyticsService::filters(['date_to' => '2026-01-01']);
$check($fromOnly['valid'] === false && $toOnly['valid'] === false, 'One-sided date ranges are rejected');
$wide = SecurityAnalyticsService::filters(['date_from' => '2025-01-01', 'date_to' => '2026-12-31']);
$check($wide['valid'] === false, 'Analytics date ranges remain bounded to 366 days');
$check(SecurityAnalyticsService::exportFilterKeys('security_events') === ['date_from','date_to','category','type','severity','threat_level','profile','module'], 'Event export declares complete event-filter semantics');
$sessionFilters = SecurityAnalyticsService::filters(['date_from'=>'2026-01-01','date_to'=>'2026-01-02','threat_level'=>'LOW']);
$check(SecurityAnalyticsService::exportFilterErrors('security_sessions', $sessionFilters) === [], 'Session export accepts its documented filters');
$unsupported = SecurityAnalyticsService::filters(['type' => 'LOGIN_FAILURE']);
$check(SecurityAnalyticsService::exportFilterErrors('security_sessions', $unsupported) !== [], 'Unsupported session-export filters are rejected');
$check(SecurityAnalyticsService::exportFilterErrors('session_evidence', $unsupported) !== [], 'Session evidence rejects unrelated filters');
$check(str_contains($service, "SELECT id FROM security_sessions ORDER BY last_seen_at DESC,id DESC LIMIT 1"), 'Generic session evidence export selects exactly one deterministic latest session');

$check(!preg_match('/SELECT[^;]+s\.source_hash/is', $service), 'Analytics presentation queries do not select the internal source hash');
$check(!preg_match('/source_identifier|source_hash/i', $sessionView), 'Session HTML contains no source identifier presentation');
$check(!preg_match('/[\'\"]source_identifier[\'\"]\s*=>/i', $service), 'Analytics model output contains no source identifier alias');
$check(str_contains($service, 'safeMetadataView') && !preg_match('/\$allowed=\[[^;]*(?:source_ip|source_safe_identifier)/is', $service), 'Event metadata allowlist excludes raw and safe source identifiers');
$check(str_contains($api, "'INVALID_FILTER'") && str_contains($api, '422'), 'Analytics API rejects invalid filters with a safe 422 response');
$check(str_contains($service, "return ['WHERE 1=0', []]") || str_contains($service, "return['WHERE 1=0',[]]"), 'Invalid filters have a defensive no-results query boundary');
$check(str_contains($controller, 'exportFilterKeys') && str_contains($controller, "'event_type'") && str_contains($dashboard, 'Applicable active filters are preserved'), 'Dashboard exports preserve applicable filters without parameter-name collision');

$check(SecurityAnalyticsService::MAX_TIMELINE === 200 && SecurityAnalyticsService::MAX_EXPORT === 1000, 'Timeline and export limits remain explicitly bounded');
$check(str_contains($service, 'timelineRows($filters,self::MAX_EXPORT,self::MAX_EXPORT'), 'Event exports use the documented 1,000-row boundary');
$check(str_contains($service, "LIMIT ' . self::MAX_EXPORT"), 'LAB module export query has an explicit row bound');
$check(str_contains($service, 'ORDER BY e.created_at DESC,e.id DESC'), 'Event timeline ordering is deterministic');
$check(str_contains($service, 'ORDER BY c.created_at DESC,c.id DESC'), 'Contributor export ordering is deterministic');
$check(!preg_match('/\b(INSERT|UPDATE|DELETE|REPLACE|ALTER|DROP|TRUNCATE)\b/i', $service . $export), 'Analytics and export services contain no database mutation statement');
$check(!preg_match('/SecurityEventService::record|ThreatScoringService::apply|AdaptiveDeceptionService::select|changeState\s*\(/', $service . $export), 'Analytics/export invokes no telemetry, scoring, adaptive, or LAB mutation service');

foreach (['=SUM(A1:A2)', '+cmd', '-2+3', '@IMPORTXML', " \t=HYPERLINK(\"x\")"] as $value) {
    $check(str_starts_with(EvidenceExportService::neutralizeCsvCell($value), "'"), 'CSV formula-like field is neutralized');
}
$check(EvidenceExportService::neutralizeCsvCell("safe,quoted\nvalue") === "safe,quoted\nvalue", 'Ordinary CSV text remains unchanged before fputcsv quoting');
$check(EvidenceExportService::generate('unknown', 'json', $valid) === null && EvidenceExportService::generate('security_events', 'xml', $valid) === null, 'Unsupported export type and format are rejected');

foreach (['/security/analytics','/security/analytics/sessions/{id}','/api/security/analytics/summary','/api/security/analytics/timeline','/api/security/analytics/sessions/{id}','/api/security/analytics/lab','/api/security/analytics/export'] as $path) {
    $check(preg_match('#' . preg_quote($path, '#') . "'.*new RequireRole\(\['security_admin'\]\)#", $routes) === 1, "{$path} remains Security Admin-only");
}
$check(ThreatScoringService::weight('DECOY_ACCESSED') === 20 && ThreatScoringService::weight('HONEYTOKEN_TRIGGERED') === 35, 'H14 deception scoring weights remain unchanged');
$check(ThreatScoringService::weight('ADAPTIVE_DECOY_RENDERED') === 0, 'Adaptive analytics telemetry remains zero-weight');
$check(str_contains($labEnvironment, 'VULNERABILITY_LAB_ENABLED=false'), 'Vulnerability LAB remains disabled by default');

echo PHP_EOL . "{$passed} H16 static/privacy checks passed, {$failed} failed." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
