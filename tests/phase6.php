<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Security\SecurityEventTaxonomy;
use App\Services\AdaptiveDeceptionService;
use App\Services\ThreatScoringService;

$passes = 0;
$failures = 0;
$check = static function (bool $condition, string $label) use (&$passes, &$failures): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . "\n";
    $condition ? $passes++ : $failures++;
};

$policy = AdaptiveDeceptionService::policy();
$check(array_keys($policy) === ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 'Policy defines exactly four ordered deception profiles');
$check(AdaptiveDeceptionService::profileForLevel(ThreatScoringService::classification(0))['name'] === 'LOW' && AdaptiveDeceptionService::profileForLevel(ThreatScoringService::classification(19))['name'] === 'LOW', 'Scores 0-19 select LOW');
$check(AdaptiveDeceptionService::profileForLevel(ThreatScoringService::classification(20))['name'] === 'MEDIUM' && AdaptiveDeceptionService::profileForLevel(ThreatScoringService::classification(44))['name'] === 'MEDIUM', 'Scores 20-44 select MEDIUM');
$check(AdaptiveDeceptionService::profileForLevel(ThreatScoringService::classification(45))['name'] === 'HIGH' && AdaptiveDeceptionService::profileForLevel(ThreatScoringService::classification(74))['name'] === 'HIGH', 'Scores 45-74 select HIGH');
$check(AdaptiveDeceptionService::profileForLevel(ThreatScoringService::classification(75))['name'] === 'CRITICAL' && AdaptiveDeceptionService::profileForLevel(ThreatScoringService::classification(100))['name'] === 'CRITICAL', 'Scores 75-100 select CRITICAL');
$check(AdaptiveDeceptionService::profileForLevel('UNAVAILABLE')['name'] === 'LOW', 'Unavailable assessment maps to safe LOW fallback');
$check($policy['LOW']['metadata_richness'] < $policy['MEDIUM']['metadata_richness'] && $policy['MEDIUM']['metadata_richness'] < $policy['HIGH']['metadata_richness'] && $policy['HIGH']['metadata_richness'] < $policy['CRITICAL']['metadata_richness'], 'Synthetic metadata richness increases deterministically');
$check($policy['LOW']['honeytoken_identifiers'] === [] && $policy['MEDIUM']['honeytoken_identifiers'] === [], 'LOW and MEDIUM expose no honeytoken');
$check($policy['HIGH']['honeytoken_identifiers'] === ['HT-API-001'], 'HIGH exposes one controlled registry identifier');
$check($policy['CRITICAL']['honeytoken_identifiers'] === ['HT-API-001', 'HT-BACKUP-001'], 'CRITICAL exposes the controlled registered set');
foreach (['DECEPTION_PROFILE_SELECTED', 'DECEPTION_PROFILE_CHANGED', 'ADAPTIVE_DECOY_RENDERED'] as $type) {
    $check(SecurityEventTaxonomy::definition($type)['category'] === 'DECEPTION' && ThreatScoringService::weight($type) === 0, "{$type} is non-scoring deception telemetry");
}

$service = (string) file_get_contents($root . '/app/Services/AdaptiveDeceptionService.php');
$sessionService = (string) file_get_contents($root . '/app/Services/SecuritySessionService.php');
$routes = (string) file_get_contents($root . '/routes/web.php');
$check(str_contains($service, "return self::context('LOW', null, 0, 'LOW', null, true)"), 'Selection failure has an explicit safe LOW fallback');
$check(str_contains($service, "adaptive marker resolution failed; no markers exposed") && str_contains($service, 'return []'), 'Marker-registry failure falls back to exposing no marker');
$check(str_contains($service, 'previous') && str_contains($service, 'ORDER[$previous] > self::ORDER[$level]'), 'Active-session profile downgrades are prevented');
$check(str_contains($sessionService, "eventType !== 'DECOY_ACCESSED'") && str_contains($sessionService, 'return (int) $statement->fetchColumn() > 0 ? 0 : $weight'), 'Repeated same-decoy access is deduplicated for scoring');
$check(substr_count($routes, "new RequireRole(['security_admin'])") >= 20, 'Adaptive dashboard and APIs require exact Security Admin role');
foreach (['/api/security/adaptive/summary', '/api/security/sessions/{id}/deception', '/api/security/adaptive/events'] as $route) {
    $check(str_contains($routes, "'{$route}'"), "Adaptive route {$route} is registered");
}
$realControllers = '';
foreach (['AuthController.php', 'ProfileController.php', 'DocumentController.php', 'ApiController.php', 'AdminController.php'] as $file) {
    $realControllers .= (string) file_get_contents($root . '/app/Controllers/' . $file);
}
$check(!str_contains($realControllers, 'AdaptiveDeceptionService'), 'Legitimate application controllers do not invoke adaptive deception');
$check(!preg_match('/shell_exec|passthru|proc_open|popen|firewall|suspend.*user|update\s+users\s+set\s+role/i', $service), 'Adaptive service contains no command, blocking, suspension, or role mutation behavior');
$check(!preg_match('/Document|password|DB_PASSWORD|filesystem|\.env/i', var_export($policy, true)), 'Profile policy contains no real application data or secret references');

echo "\n{$passes} Phase 6 checks passed, {$failures} failed.\n";
exit($failures === 0 ? 0 : 1);
