<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/app/Core/Env.php';
App\Core\Env::load($root . '/.env');

if ((string) getenv('TEST_DB_DATABASE') !== 'chimera_test') {
    echo "[FAIL] TEST_DB_DATABASE must be exactly chimera_test." . PHP_EOL;
    exit(1);
}

putenv('DB_DATABASE=chimera_test');
$_ENV['DB_DATABASE'] = 'chimera_test';
putenv('DB_USERNAME=' . (string) getenv('TEST_DB_USERNAME'));
$_ENV['DB_USERNAME'] = (string) getenv('TEST_DB_USERNAME');
putenv('DB_PASSWORD=' . (string) getenv('TEST_DB_PASSWORD'));
$_ENV['DB_PASSWORD'] = (string) getenv('TEST_DB_PASSWORD');
require $root . '/bootstrap/app.php';

use App\Core\Database;
use App\Services\EvidenceExportService;
use App\Services\SecurityAnalyticsService;

$database = Database::connection();
$connection = $database->query('SELECT DATABASE() database_name, @@port server_port, CURRENT_USER() authenticated_user')->fetch();
if ($connection['database_name'] !== 'chimera_test' || (int) $connection['server_port'] !== 3308 || !str_starts_with($connection['authenticated_user'], 'chimera_test_app@')) {
    echo "[FAIL] Unsafe H16 integration target." . PHP_EOL;
    exit(1);
}

$starts = [];
foreach (['security_events', 'security_sessions', 'security_score_contributors'] as $table) {
    $starts[$table] = (int) $database->query("SELECT COALESCE(MAX(id),0) FROM {$table}")->fetchColumn();
}
$usersBefore = (int) $database->query('SELECT COUNT(*) FROM users')->fetchColumn();
$documentsBefore = (int) $database->query('SELECT COUNT(*) FROM documents')->fetchColumn();
$labBefore = (string) $database->query("SELECT COALESCE(GROUP_CONCAT(CONCAT(id, ':', state) ORDER BY id SEPARATOR ','), '') FROM vulnerability_modules")->fetchColumn();

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};

$sourceFixture = 'h16-internal-source-fixture';
$rawFixture = 'h16-legacy-raw-fixture';

try {
    $insertSession = $database->prepare("INSERT INTO security_sessions(session_identifier,user_id,source_hash,user_agent_hash,threat_score,classification,request_count,first_seen_at,last_seen_at) VALUES(UUID(),NULL,:source,NULL,0,'LOW',0,'2038-04-01 00:00:00','2038-04-01 00:00:00')");
    $insertSession->execute(['source' => hash('sha256', $sourceFixture)]);
    $sessionId = (int) $database->lastInsertId();

    $insertEvent = $database->prepare("INSERT INTO security_events(security_session_id,event_type,source_safe_identifier,endpoint,http_method,user_agent_summary,severity,risk_delta,description,metadata_json,created_at) VALUES(:session_id,:type,:safe_source,:endpoint,'GET','CHIMERA H16 Local Test',:severity,0,'H16 deterministic analytics fixture.',:metadata,:created_at)");
    $legacyMetadata = json_encode(['category'=>'REQUEST_SECURITY','outcome'=>'REJECTED','source_ip'=>$rawFixture,'source_safe_identifier'=>$sourceFixture,'target_identifier'=>'=FORMULA-LIKE-SYNTHETIC'], JSON_THROW_ON_ERROR);
    for ($index = 0; $index < 1001; $index++) {
        $insertEvent->execute([
            'session_id' => $sessionId,
            'type' => 'INVALID_REQUEST',
            'safe_source' => hash('sha256', $sourceFixture),
            'endpoint' => $index === 0 ? "/h16,quoted\npath" : '/h16/fixture',
            'severity' => 'LOW',
            'metadata' => $legacyMetadata,
            'created_at' => '2038-04-01 00:00:00',
        ]);
    }

    $filters = SecurityAnalyticsService::filters(['date_from'=>'2038-04-01','date_to'=>'2038-04-01']);
    $dashboard = SecurityAnalyticsService::dashboard($filters);
    $check($dashboard['events']['total'] === 1001, 'Analytics total matches the deterministic fixture count');
    $byType = array_column($dashboard['events']['by_type'], 'total', 'label');
    $bySeverity = array_column($dashboard['events']['by_severity'], 'total', 'label');
    $check(($byType['INVALID_REQUEST'] ?? 0) === 1001, 'Event-type aggregation matches source data');
    $check(($bySeverity['LOW'] ?? 0) === 1001, 'Severity aggregation matches source data');

    $timeline = SecurityAnalyticsService::timeline($filters, 200);
    $check(count($timeline) === 200, 'Interactive timeline is bounded to 200 rows');
    $ordered = true;
    for ($i = 1; $i < count($timeline); $i++) if ($timeline[$i - 1]['event_id'] <= $timeline[$i]['event_id']) $ordered = false;
    $check($ordered, 'Equal-timestamp timeline rows use deterministic descending ID order');

    $eventExport = SecurityAnalyticsService::exportRows('security_events', $filters);
    $check(is_array($eventExport) && count($eventExport) === 1000, 'Security-event export is bounded to exactly 1,000 rows');
    $eventJson = json_encode($eventExport, JSON_THROW_ON_ERROR);
    $check(!preg_match('/source_ip|source_safe_identifier|source_identifier|source_hash/i', $eventJson), 'Legacy event export omits all raw and internal source fields');
    $check(!str_contains($eventJson, $rawFixture) && !str_contains($eventJson, $sourceFixture), 'Legacy source fixture values do not cross the export boundary');

    $sessionListJson = json_encode($dashboard['session_list'], JSON_THROW_ON_ERROR);
    $analysis = SecurityAnalyticsService::sessionAnalysis($sessionId);
    $analysisJson = json_encode($analysis, JSON_THROW_ON_ERROR);
    $sessionExport = EvidenceExportService::generate('session_evidence', 'json', SecurityAnalyticsService::filters([]), $sessionId);
    $csvExport = EvidenceExportService::generate('session_evidence', 'csv', SecurityAnalyticsService::filters([]), $sessionId);
    $genericSessionExport = EvidenceExportService::generate('session_evidence', 'json', SecurityAnalyticsService::filters([]));
    $genericDecoded = json_decode($genericSessionExport['body'] ?? '', true);
    $check(is_array($genericDecoded) && count($genericDecoded['data'] ?? []) === 1, 'Exact generic session evidence contract returns one bounded latest-session record');
    $allSessionOutput = $sessionListJson . $analysisJson . ($sessionExport['body'] ?? '') . ($csvExport['body'] ?? '') . ($genericSessionExport['body'] ?? '');
    $check(!preg_match('/source_ip|source_safe_identifier|source_identifier|source_hash/i', $allSessionOutput), 'Session list, detail, JSON, and CSV exports omit source identifiers');
    $check(!str_contains($allSessionOutput, $rawFixture) && !str_contains($allSessionOutput, $sourceFixture), 'Session presentation never emits source fixture values');
    $check(($analysis['session']['evidence_id'] ?? '') !== '', 'Stable evidence ID remains available after source-field removal');
    $check(str_contains($csvExport['content_type'] ?? '', 'text/csv') && str_contains($csvExport['body'] ?? '', 'evidence_id'), 'Session evidence CSV remains structurally valid');

    $bad = SecurityAnalyticsService::filters(['severity'=>'ROOT']);
    $check($bad['valid'] === false && SecurityAnalyticsService::dashboard($bad)['events']['total'] === 0, 'Invalid dashboard filters return no data rather than broadening results');
    $check(SecurityAnalyticsService::timeline($bad, 100) === [], 'Invalid timeline filters return no rows');
    $check(EvidenceExportService::generate('security_events', 'json', $bad) === null, 'Invalid export filters produce no export');
    $check(EvidenceExportService::generate('security_sessions', 'json', SecurityAnalyticsService::filters(['type'=>'LOGIN_FAILURE'])) === null, 'Unsupported export-filter combinations fail closed');
    $check(SecurityAnalyticsService::filters(['date_from'=>'2038-04-01'])['valid'] === false, 'One-sided date filtering fails closed');

    $emptyFilters = SecurityAnalyticsService::filters(['date_from'=>'2040-01-01','date_to'=>'2040-01-01']);
    $check(SecurityAnalyticsService::dashboard($emptyFilters)['events']['total'] === 0 && SecurityAnalyticsService::timeline($emptyFilters, 10) === [], 'Empty analytics periods are handled safely');

    $snapshotBefore = [(int)$database->query('SELECT COUNT(*) FROM security_events')->fetchColumn(),(int)$database->query('SELECT COUNT(*) FROM security_sessions')->fetchColumn(),(int)$database->query('SELECT COUNT(*) FROM security_score_contributors')->fetchColumn(),(int)$database->query('SELECT COUNT(*) FROM users')->fetchColumn(),(int)$database->query('SELECT COUNT(*) FROM documents')->fetchColumn(),(string)$database->query("SELECT COALESCE(GROUP_CONCAT(CONCAT(id, ':', state) ORDER BY id SEPARATOR ','), '') FROM vulnerability_modules")->fetchColumn()];
    SecurityAnalyticsService::dashboard($filters);
    EvidenceExportService::generate('security_events', 'csv', $filters);
    $snapshotAfter = [(int)$database->query('SELECT COUNT(*) FROM security_events')->fetchColumn(),(int)$database->query('SELECT COUNT(*) FROM security_sessions')->fetchColumn(),(int)$database->query('SELECT COUNT(*) FROM security_score_contributors')->fetchColumn(),(int)$database->query('SELECT COUNT(*) FROM users')->fetchColumn(),(int)$database->query('SELECT COUNT(*) FROM documents')->fetchColumn(),(string)$database->query("SELECT COALESCE(GROUP_CONCAT(CONCAT(id, ':', state) ORDER BY id SEPARATOR ','), '') FROM vulnerability_modules")->fetchColumn()];
    $check($snapshotBefore === $snapshotAfter, 'Authorized analytics and export operations are read-only');
    $check($usersBefore === $snapshotAfter[3] && $documentsBefore === $snapshotAfter[4] && $labBefore === $snapshotAfter[5], 'Users, documents, roles, and LAB state remain unchanged');
} finally {
    $database->exec("DELETE FROM security_score_contributors WHERE id > {$starts['security_score_contributors']}");
    $database->exec("DELETE FROM security_events WHERE id > {$starts['security_events']}");
    $database->exec("DELETE FROM security_sessions WHERE id > {$starts['security_sessions']}");
}

$residual = (int) $database->query("SELECT (SELECT COUNT(*) FROM security_score_contributors WHERE id > {$starts['security_score_contributors']}) + (SELECT COUNT(*) FROM security_events WHERE id > {$starts['security_events']}) + (SELECT COUNT(*) FROM security_sessions WHERE id > {$starts['security_sessions']})")->fetchColumn();
$check($residual === 0, 'H16 integration removes all exact test fixtures');

echo 'Cleanup: ' . ($residual === 0 ? 'PASS' : 'FAIL') . PHP_EOL;
echo PHP_EOL . "{$passed} H16 integration/privacy checks passed, {$failed} failed." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
