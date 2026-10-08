<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/app/Core/Env.php';
App\Core\Env::load($root . '/.env');

if ((string) getenv('TEST_DB_DATABASE') !== 'chimera_test') {
    echo "[FAIL] TEST_DB_DATABASE must be exactly chimera_test." . PHP_EOL;
    exit(1);
}

$testUsername = (string) getenv('TEST_DB_USERNAME');
$testPassword = (string) getenv('TEST_DB_PASSWORD');
if ($testUsername === '' || $testPassword === '') {
    echo "[FAIL] Dedicated chimera_test credentials are required." . PHP_EOL;
    exit(1);
}

putenv('DB_DATABASE=chimera_test');
$_ENV['DB_DATABASE'] = 'chimera_test';
putenv('DB_USERNAME=' . $testUsername);
$_ENV['DB_USERNAME'] = $testUsername;
putenv('DB_PASSWORD=' . $testPassword);
$_ENV['DB_PASSWORD'] = $testPassword;
require $root . '/bootstrap/app.php';

use App\Core\Database;
use App\Core\Request;
use App\Services\SecurityEventService;
use App\Services\SecuritySessionService;

$database = Database::connection();
$connection = $database->query('SELECT DATABASE() database_name, @@port server_port, CURRENT_USER() authenticated_user')->fetch();
if (
    !is_array($connection)
    || ($connection['database_name'] ?? '') !== 'chimera_test'
    || (int) ($connection['server_port'] ?? 0) !== 3308
    || !str_starts_with((string) ($connection['authenticated_user'] ?? ''), 'chimera_test_app@')
) {
    echo "[FAIL] Unsafe H14 integration target." . PHP_EOL;
    exit(1);
}

$eventStart = (int) $database->query('SELECT COALESCE(MAX(id), 0) FROM security_events')->fetchColumn();
$sessionStart = (int) $database->query('SELECT COALESCE(MAX(id), 0) FROM security_sessions')->fetchColumn();
$contributorStart = (int) $database->query('SELECT COALESCE(MAX(id), 0) FROM security_score_contributors')->fetchColumn();
$userStart = (int) $database->query('SELECT COALESCE(MAX(id), 0) FROM users')->fetchColumn();

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
$classification = static fn (int $score): string => $score >= 75 ? 'CRITICAL' : ($score >= 45 ? 'HIGH' : ($score >= 20 ? 'MEDIUM' : 'LOW'));
$request = static function (int $suffix, string $path): Request {
    return new Request('GET', $path, [], [], [
        'REMOTE_ADDR' => '198.51.100.' . $suffix,
        'HTTP_USER_AGENT' => 'CHIMERA H14 Local Validation',
    ]);
};
$positiveEventIds = [];
$createdUserId = null;

try {
    foreach (array_values($expectedRules) as $index => $unused) {
        if ($index + 10 > 250) {
            throw new RuntimeException('Fixture source range exhausted.');
        }
    }

    foreach ($expectedRules as $eventType => $weight) {
        $suffix = 10 + count($positiveEventIds);
        $context = $eventType === 'DECOY_ACCESSED'
            ? ['target_type' => 'decoy', 'target_identifier' => 'DEC-H14-' . $suffix]
            : [];
        $eventId = SecurityEventService::record($request($suffix, '/h14/rule/' . strtolower($eventType)), $eventType, null, $context);
        if ($eventId === null) {
            $check(false, "{$eventType} fixture records successfully");
            continue;
        }
        $positiveEventIds[] = $eventId;
        $eventStatement = $database->prepare('SELECT security_session_id,event_type,risk_delta FROM security_events WHERE id=:id');
        $eventStatement->execute(['id' => $eventId]);
        $event = $eventStatement->fetch();
        $sessionId = (int) ($event['security_session_id'] ?? 0);
        $sessionStatement = $database->prepare('SELECT threat_score,classification FROM security_sessions WHERE id=:id');
        $sessionStatement->execute(['id' => $sessionId]);
        $session = $sessionStatement->fetch();
        $contributorStatement = $database->prepare("SELECT security_session_id,rule_code,risk_delta FROM security_score_contributors WHERE security_session_id=:session_id AND label LIKE :label");
        $contributorStatement->execute(['session_id' => $sessionId, 'label' => 'Event #' . $eventId . ':%']);
        $contributors = $contributorStatement->fetchAll();
        $check(
            is_array($event)
            && is_array($session)
            && $sessionId > 0
            && $event['event_type'] === $eventType
            && (int) $event['risk_delta'] === $weight
            && count($contributors) === 1
            && (int) $contributors[0]['security_session_id'] === $sessionId
            && $contributors[0]['rule_code'] === $eventType
            && (int) $contributors[0]['risk_delta'] === $weight
            && (int) $session['threat_score'] === $weight
            && $session['classification'] === $classification($weight),
            "{$eventType} persists matching event, contributor, score, and classification"
        );
    }

    $zeroEvent = SecurityEventService::record($request(40, '/h14/zero-weight'), 'LOGIN_SUCCESS');
    $zeroRow = $database->query('SELECT security_session_id,risk_delta FROM security_events WHERE id=' . (int) $zeroEvent)->fetch();
    $zeroSessionId = (int) ($zeroRow['security_session_id'] ?? 0);
    $zeroScore = (int) $database->query('SELECT threat_score FROM security_sessions WHERE id=' . $zeroSessionId)->fetchColumn();
    $zeroContributors = (int) $database->query("SELECT COUNT(*) FROM security_score_contributors WHERE label LIKE 'Event #" . (int) $zeroEvent . ":%'")->fetchColumn();
    $check($zeroSessionId > 0 && (int) $zeroRow['risk_delta'] === 0 && $zeroScore === 0 && $zeroContributors === 0, 'Zero-weight event correlates without score increase or contributor');

    $repeatRequest = $request(41, '/h14/repeated-legitimate');
    $repeatOne = SecurityEventService::record($repeatRequest, 'LOGIN_FAILURE');
    $repeatTwo = SecurityEventService::record($repeatRequest, 'LOGIN_FAILURE');
    $repeatSessionId = (int) $database->query('SELECT security_session_id FROM security_events WHERE id=' . (int) $repeatTwo)->fetchColumn();
    $repeatScore = (int) $database->query('SELECT threat_score FROM security_sessions WHERE id=' . $repeatSessionId)->fetchColumn();
    $repeatContributors = (int) $database->query("SELECT COUNT(*) FROM security_score_contributors WHERE security_session_id={$repeatSessionId} AND rule_code='LOGIN_FAILURE'")->fetchColumn();
    $check($repeatOne !== $repeatTwo && $repeatScore === 10 && $repeatContributors === 2, 'Separate identical legitimate events accumulate deterministically');

    $beforeReplay = $database->query("SELECT threat_score,(SELECT COUNT(*) FROM security_score_contributors WHERE security_session_id={$repeatSessionId}) contributor_count FROM security_sessions WHERE id={$repeatSessionId}")->fetch();
    $replayedSession = SecuritySessionService::correlate((int) $repeatTwo);
    $afterReplay = $database->query("SELECT threat_score,(SELECT COUNT(*) FROM security_score_contributors WHERE security_session_id={$repeatSessionId}) contributor_count FROM security_sessions WHERE id={$repeatSessionId}")->fetch();
    $check($replayedSession === $repeatSessionId && $beforeReplay === $afterReplay, 'Reprocessing the same event is idempotent');

    $decoyRequest = $request(42, '/h14/repeated-decoy');
    $decoyContext = ['target_type' => 'decoy', 'target_identifier' => 'DEC-H14-REPEAT'];
    $decoyOne = SecurityEventService::record($decoyRequest, 'DECOY_ACCESSED', null, $decoyContext);
    $decoyTwo = SecurityEventService::record($decoyRequest, 'DECOY_ACCESSED', null, $decoyContext);
    $decoyRows = $database->query('SELECT id,security_session_id,risk_delta FROM security_events WHERE id IN (' . (int) $decoyOne . ',' . (int) $decoyTwo . ') ORDER BY id')->fetchAll();
    $decoySessionId = (int) $decoyRows[0]['security_session_id'];
    $decoyScore = (int) $database->query('SELECT threat_score FROM security_sessions WHERE id=' . $decoySessionId)->fetchColumn();
    $decoyContributors = (int) $database->query("SELECT COUNT(*) FROM security_score_contributors WHERE security_session_id={$decoySessionId} AND rule_code='DECOY_ACCESSED'")->fetchColumn();
    $check(count($decoyRows) === 2 && (int) $decoyRows[0]['risk_delta'] === 20 && (int) $decoyRows[1]['risk_delta'] === 0 && $decoyScore === 20 && $decoyContributors === 1, 'Repeated same-decoy access is suppressed after the first contribution');

    $saturationRequest = $request(43, '/h14/saturation');
    $saturationEvents = [];
    for ($index = 0; $index < 3; $index++) {
        $saturationEvents[] = SecurityEventService::record($saturationRequest, 'HONEYTOKEN_TRIGGERED');
    }
    $saturationSessionId = (int) $database->query('SELECT security_session_id FROM security_events WHERE id=' . (int) end($saturationEvents))->fetchColumn();
    $saturationSession = $database->query('SELECT threat_score,classification FROM security_sessions WHERE id=' . $saturationSessionId)->fetch();
    $saturationEvidence = $database->query("SELECT COUNT(*) contributor_count,COALESCE(SUM(risk_delta),0) contributor_total,MIN(risk_delta) minimum_delta,MAX(risk_delta) maximum_delta FROM security_score_contributors WHERE security_session_id={$saturationSessionId}")->fetch();
    $check(
        (int) $saturationEvidence['contributor_count'] === 3
        && (int) $saturationEvidence['contributor_total'] === 105
        && (int) $saturationEvidence['minimum_delta'] === 35
        && (int) $saturationEvidence['maximum_delta'] === 35
        && (int) $saturationSession['threat_score'] === 100
        && $saturationSession['classification'] === 'CRITICAL',
        'Contributor evidence retains full weights while persisted and reconstructed score saturate at 100'
    );

    $userStatement = $database->prepare('INSERT INTO users(name,email,password_hash,role,is_active) VALUES(?,?,?,?,1)');
    $userStatement->execute(['H14 Actor', 'h14-' . bin2hex(random_bytes(6)) . '@test.chimera', password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT), 'user']);
    $createdUserId = (int) $database->lastInsertId();
    $boundaryRequest = $request(44, '/h14/actor-boundary');
    $anonymousEvent = SecurityEventService::record($boundaryRequest, 'ACCESS_DENIED');
    $authenticatedEvent = SecurityEventService::record($boundaryRequest, 'ACCESS_DENIED', $createdUserId);
    $anonymousSession = (int) $database->query('SELECT security_session_id FROM security_events WHERE id=' . (int) $anonymousEvent)->fetchColumn();
    $authenticatedSession = (int) $database->query('SELECT security_session_id FROM security_events WHERE id=' . (int) $authenticatedEvent)->fetchColumn();
    $check($anonymousSession > 0 && $authenticatedSession > 0 && $anonymousSession !== $authenticatedSession, 'Authenticated and anonymous observations remain in separate sessions');

    $windowRequest = $request(45, '/h14/window-boundary');
    $windowOne = SecurityEventService::record($windowRequest, 'ACCESS_DENIED');
    $oldSession = (int) $database->query('SELECT security_session_id FROM security_events WHERE id=' . (int) $windowOne)->fetchColumn();
    $database->exec("UPDATE security_sessions SET last_seen_at=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 31 MINUTE) WHERE id={$oldSession}");
    $windowTwo = SecurityEventService::record($windowRequest, 'ACCESS_DENIED');
    $newSession = (int) $database->query('SELECT security_session_id FROM security_events WHERE id=' . (int) $windowTwo)->fetchColumn();
    $check($oldSession > 0 && $newSession > 0 && $oldSession !== $newSession, 'Expired 30-minute session is not reused');

    $consistency = $database->query(
        "SELECT COUNT(*) FROM security_score_contributors c
         LEFT JOIN security_events e
           ON e.id=CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(c.label,'Event #',-1),':',1) AS UNSIGNED)
         WHERE c.id>{$contributorStart}
           AND (e.id IS NULL OR e.security_session_id<>c.security_session_id OR e.event_type<>c.rule_code OR e.risk_delta<>c.risk_delta)"
    )->fetchColumn();
    $check((int) $consistency === 0, 'Every positive H14 contributor resolves to a matching event, session, rule, and delta');

    $labSessionCountBefore = (int) $database->query('SELECT COUNT(*) FROM security_sessions')->fetchColumn();
    $labEvent = SecurityEventService::record($request(46, '/lab/h14-isolation'), 'LAB_MODULE_ACCESSED', null, ['target_type' => 'lab_module', 'target_identifier' => 'CHIM-VULN-001']);
    $labRow = $database->query('SELECT security_session_id,risk_delta FROM security_events WHERE id=' . (int) $labEvent)->fetch();
    $labContributorCount = (int) $database->query("SELECT COUNT(*) FROM security_score_contributors WHERE label LIKE 'Event #" . (int) $labEvent . ":%'")->fetchColumn();
    $labSessionCountAfter = (int) $database->query('SELECT COUNT(*) FROM security_sessions')->fetchColumn();
    $check($labRow['security_session_id'] === null && (int) $labRow['risk_delta'] === 0 && $labContributorCount === 0 && $labSessionCountBefore === $labSessionCountAfter, 'LAB event remains outside operational sessions and scoring');

    echo '[INFO] Transaction failure injection NOT EXERCISED: deterministic injection would require an invasive trigger, schema change, or application seam not present in the production architecture.' . PHP_EOL;
    $serviceSource = (string) file_get_contents($root . '/app/Services/SecuritySessionService.php');
    $check(
        str_contains($serviceSource, 'beginTransaction()')
        && str_contains($serviceSource, 'rollBack()')
        && str_contains($serviceSource, 'security_session_id IS NULL')
        && str_contains($serviceSource, 'rowCount() !== 1'),
        'Transaction rollback and concurrent-linkage guards remain present'
    );
} catch (Throwable $exception) {
    $failed++;
    echo '[FAIL] H14 integration exception: ' . $exception->getMessage() . PHP_EOL;
} finally {
    $database->exec('DELETE FROM security_events WHERE id>' . $eventStart);
    $database->exec('DELETE FROM security_sessions WHERE id>' . $sessionStart);
    if ($createdUserId !== null) {
        $deleteUser = $database->prepare('DELETE FROM users WHERE id=:id');
        $deleteUser->execute(['id' => $createdUserId]);
    }
}

$remainingEvents = (int) $database->query('SELECT COUNT(*) FROM security_events WHERE id>' . $eventStart)->fetchColumn();
$remainingSessions = (int) $database->query('SELECT COUNT(*) FROM security_sessions WHERE id>' . $sessionStart)->fetchColumn();
$remainingContributors = (int) $database->query('SELECT COUNT(*) FROM security_score_contributors WHERE id>' . $contributorStart)->fetchColumn();
$remainingUsers = (int) $database->query('SELECT COUNT(*) FROM users WHERE id>' . $userStart)->fetchColumn();
$check($remainingEvents === 0 && $remainingSessions === 0 && $remainingContributors === 0 && $remainingUsers === 0, 'H14 integration fixtures are fully cleaned from chimera_test');

echo PHP_EOL . "{$passed} H14 integration checks passed, {$failed} failed." . PHP_EOL;
exit($failed === 0 ? 0 : 1);

