<?php

declare(strict_types=1);

use App\Core\Env;

$root = dirname(__DIR__);
require $root . '/app/Core/Env.php';
Env::load($root . '/.env');

if ((string) getenv('TEST_DB_DATABASE') !== 'chimera_test' || (string) getenv('DB_DATABASE') !== 'chimera' || (string) getenv('DB_PORT') !== '3308') {
    echo "[FAIL] H18 HTTP database guards are not configured safely." . PHP_EOL;
    exit(1);
}
$testUser = (string) getenv('TEST_DB_USERNAME');
$testPassword = (string) getenv('TEST_DB_PASSWORD');
if ($testUser === '' || $testPassword === '') {
    echo "[FAIL] Dedicated test credentials are required." . PHP_EOL;
    exit(1);
}
$database = new PDO(
    'mysql:host=127.0.0.1;port=3308;dbname=chimera_test;charset=utf8mb4',
    $testUser,
    $testPassword,
    [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES=>false]
);
$connection = $database->query('SELECT DATABASE() database_name,@@port server_port,CURRENT_USER() authenticated_user')->fetch();
if (!is_array($connection) || $connection['database_name'] !== 'chimera_test' || (int) $connection['server_port'] !== 3308 || !str_starts_with((string) $connection['authenticated_user'], 'chimera_test_app@')) {
    echo "[FAIL] Unsafe H18 HTTP target." . PHP_EOL;
    exit(1);
}

$trackedTables = ['users','documents','user_activity','security_events','security_sessions','security_score_contributors'];
$starts = [];
foreach ($trackedTables as $table) {
    $starts[$table] = (int) $database->query("SELECT COALESCE(MAX(id),0) FROM {$table}")->fetchColumn();
}
$labBefore = (string) $database->query("SELECT COALESCE(GROUP_CONCAT(CONCAT(id,':',state,':',is_active) ORDER BY id SEPARATOR ','),'') FROM vulnerability_modules")->fetchColumn();
$labHistoryBefore = (int) $database->query('SELECT COUNT(*) FROM vulnerability_state_changes')->fetchColumn();

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};

function h18Client(): CurlHandle
{
    $client = curl_init();
    curl_setopt($client, CURLOPT_COOKIEFILE, '');
    curl_setopt($client, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($client, CURLOPT_HEADER, true);
    curl_setopt($client, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($client, CURLOPT_TIMEOUT, 10);
    return $client;
}

function h18Request(CurlHandle $client, string $base, string $method, string $path, array|string|null $fields = null): array
{
    curl_setopt($client, CURLOPT_URL, $base . $path);
    curl_setopt($client, CURLOPT_CUSTOMREQUEST, $method);
    if ($method === 'GET') {
        curl_setopt($client, CURLOPT_HTTPGET, true);
        curl_setopt($client, CURLOPT_POSTFIELDS, null);
    } else {
        curl_setopt($client, CURLOPT_POST, true);
        $containsFile = is_array($fields) && array_filter($fields, static fn (mixed $value): bool => $value instanceof CURLFile) !== [];
        curl_setopt($client, CURLOPT_POSTFIELDS, $containsFile ? $fields : (is_array($fields) ? http_build_query($fields) : ($fields ?? '')));
    }
    $raw = curl_exec($client);
    if (!is_string($raw)) {
        throw new RuntimeException('H18 local HTTP request failed.');
    }
    $headerSize = curl_getinfo($client, CURLINFO_HEADER_SIZE);
    $headerText = substr($raw, 0, $headerSize);
    $headers = [];
    foreach (preg_split('/\r\n|\n|\r/', trim($headerText)) as $line) {
        if (str_contains($line, ':')) {
            [$name, $value] = explode(':', $line, 2);
            $headers[strtolower(trim($name))] = trim($value);
        }
    }
    return ['status'=>(int) curl_getinfo($client, CURLINFO_RESPONSE_CODE), 'headers'=>$headers, 'body'=>substr($raw, $headerSize)];
}

function h18Csrf(string $html): string
{
    if (!preg_match('/name="_token"\s+value="([^"]+)"/', $html, $matches)) {
        throw new RuntimeException('Expected CSRF field was not rendered.');
    }
    return html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function h18Login(CurlHandle $client, string $base, string $email, string $password): array
{
    $page = h18Request($client, $base, 'GET', '/login');
    return h18Request($client, $base, 'POST', '/login', ['_token'=>h18Csrf($page['body']), 'email'=>$email, 'password'=>$password]);
}

function h18Files(string $root, string $subdirectory = ''): array
{
    $directory = $subdirectory === '' ? $root : $root . DIRECTORY_SEPARATOR . $subdirectory;
    if (!is_dir($directory)) {
        return [];
    }
    $files = [];
    foreach (new DirectoryIterator($directory) as $entry) {
        if ($entry->isFile()) {
            $files[] = $entry->getFilename();
        }
    }
    sort($files);
    return $files;
}

function h18Snapshot(PDO $database, int $documentId, string $path, string $storage, string $labState, int $labHistory): array
{
    clearstatcache(true, $path);
    return [
        'document'=>(function () use ($database, $documentId): array|false {
            $statement = $database->prepare('SELECT * FROM documents WHERE id=:id');
            $statement->execute(['id'=>$documentId]);
            return $statement->fetch();
        })(),
        'document_count'=>(int) $database->query('SELECT COUNT(*) FROM documents')->fetchColumn(),
        'user_count'=>(int) $database->query('SELECT COUNT(*) FROM users')->fetchColumn(),
        'activity_count'=>(int) $database->query('SELECT COUNT(*) FROM user_activity')->fetchColumn(),
        'file_exists'=>is_file($path),
        'file_digest'=>is_file($path) ? hash_file('sha256', $path) : null,
        'active_files'=>h18Files($storage),
        'trash_files'=>h18Files($storage, '.trash'),
        'lab_state'=>$labState,
        'lab_history'=>$labHistory,
    ];
}

function h18SafeDenial(array $response, array $forbidden): bool
{
    if ($response['status'] !== 404 || !str_contains(strtolower($response['body']), 'not found')) {
        return false;
    }
    foreach ($forbidden as $value) {
        if ($value !== '' && str_contains($response['body'], $value)) {
            return false;
        }
    }
    return !preg_match('/source_ip|source_safe_identifier|source_identifier|source_hash|storage_name|checksum_sha256|password_hash|authorization_header|csrf_token|session_identifier/i', $response['body']);
}

$suffix = bin2hex(random_bytes(6));
$userAEmail = "h18-a-{$suffix}@e2e.chimera.test";
$userBEmail = "h18-b-{$suffix}@e2e.chimera.test";
$securityEmail = "h18-security-{$suffix}@e2e.chimera.test";
$userAName = 'H18 Owner A ' . $suffix;
$userBName = 'H18 Nonowner B ' . $suffix;
$password = 'H18-Synthetic!2026';
$originalName = "h18-private-{$suffix}.txt";
$fixtureContents = "H18 harmless two-user ownership fixture {$suffix}.\n";
$temporaryFile = tempnam(sys_get_temp_dir(), 'chimera-h18-');
file_put_contents($temporaryFile, $fixtureContents);
$fixtureDigest = hash('sha256', $fixtureContents);
$storage = $root . '/storage/uploads/h18-e2e-documents';
if (!is_dir($storage) && !mkdir($storage, 0750, true) && !is_dir($storage)) {
    echo "[FAIL] H18 isolated storage could not be created." . PHP_EOL;
    exit(1);
}
$storage = realpath($storage) ?: $storage;
$storageBefore = h18Files($storage);
$trashBefore = h18Files($storage, '.trash');
$log = $root . '/storage/logs/h18-e2e-server.log';
$clients = [];
$server = null;

try {
    $insertUser = $database->prepare('INSERT INTO users(name,email,password_hash,role,is_active) VALUES(?,?,?,?,1)');
    $insertUser->execute([$userAName, $userAEmail, password_hash($password, PASSWORD_DEFAULT), 'user']);
    $userAId = (int) $database->lastInsertId();
    $insertUser->execute([$userBName, $userBEmail, password_hash($password, PASSWORD_DEFAULT), 'user']);
    $userBId = (int) $database->lastInsertId();
    $insertUser->execute(['H18 Security Evidence Reviewer', $securityEmail, password_hash($password, PASSWORD_DEFAULT), 'security_admin']);
    $securityId = (int) $database->lastInsertId();

    $socket = stream_socket_server('tcp://127.0.0.1:0', $socketError, $socketMessage);
    if (!is_resource($socket)) {
        throw new RuntimeException('Could not allocate H18 local server port.');
    }
    $socketName = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = (int) substr(strrchr((string) $socketName, ':'), 1);
    $base = 'http://127.0.0.1:' . $port;
    $environment = getenv();
    $environment['CHIMERA_E2E_BASE_URL'] = $base;
    $environment['CHIMERA_E2E_STORAGE'] = $storage;
    $environment['VULNERABILITY_LAB_ENABLED'] = 'false';
    $environment['APP_ENV'] = 'production';
    $environment['APP_DEBUG'] = 'false';
    $server = proc_open(
        [PHP_BINARY, '-d', 'display_errors=0', '-d', 'upload_max_filesize=8M', '-d', 'post_max_size=9M', '-S', '127.0.0.1:' . $port, '-t', $root . '/public', $root . '/tests/e2e_server_router.php'],
        [0=>['pipe','r'], 1=>['file',$log,'a'], 2=>['file',$log,'a']],
        $pipes,
        $root,
        $environment
    );
    if (!is_resource($server)) {
        throw new RuntimeException('Could not start H18 local server.');
    }
    fclose($pipes[0]);
    $ready = false;
    for ($attempt = 0; $attempt < 30; $attempt++) {
        $probe = h18Client();
        try {
            $ready = h18Request($probe, $base, 'GET', '/')['status'] === 200;
        } catch (Throwable) {
            $ready = false;
        }
        curl_close($probe);
        if ($ready) break;
        usleep(100000);
    }
    if (!$ready) {
        throw new RuntimeException('H18 local server did not become ready.');
    }

    $guest = h18Client();
    $userA = h18Client();
    $userB = h18Client();
    $security = h18Client();
    $clients = [$guest,$userA,$userB,$security];

    $check(h18Login($userA, $base, $userAEmail, $password)['status'] === 302 && h18Request($userA, $base, 'GET', '/dashboard')['status'] === 200, 'USER A authenticates successfully');
    $documentsA = h18Request($userA, $base, 'GET', '/documents');
    $upload = h18Request($userA, $base, 'POST', '/documents', ['_token'=>h18Csrf($documentsA['body']), 'document'=>new CURLFile($temporaryFile, 'text/plain', $originalName)]);
    $statement = $database->prepare('SELECT * FROM documents WHERE user_id=:user_id ORDER BY id DESC LIMIT 1');
    $statement->execute(['user_id'=>$userAId]);
    $document = $statement->fetch();
    if (!is_array($document)) {
        throw new RuntimeException('USER A upload did not produce Document A.');
    }
    $documentId = (int) $document['id'];
    $storedPath = $storage . DIRECTORY_SEPARATOR . $document['storage_name'];
    $check($upload['status'] === 302 && (int) $document['user_id'] === $userAId && is_file($storedPath), 'USER A uploads exactly one owned private document');

    $listA = h18Request($userA, $base, 'GET', '/documents');
    $apiListA = h18Request($userA, $base, 'GET', '/api/documents');
    $apiA = json_decode($apiListA['body'], true);
    $apiAText = json_encode($apiA, JSON_THROW_ON_ERROR);
    $check($listA['status'] === 200 && str_contains($listA['body'], $originalName), 'USER A listing contains Document A');
    $check($apiListA['status'] === 200 && str_contains($apiAText, $originalName) && !preg_match('/storage_name|checksum_sha256|user_id|owner_/i', $apiAText), 'USER A API listing returns only authorized minimized metadata');
    $detailA = h18Request($userA, $base, 'GET', "/documents/{$documentId}");
    $downloadA = h18Request($userA, $base, 'GET', "/documents/{$documentId}/download");
    $check($detailA['status'] === 200 && str_contains($detailA['body'], $originalName), 'USER A document detail succeeds');
    $check($downloadA['status'] === 200 && hash('sha256', $downloadA['body']) === $fixtureDigest, 'USER A download bytes match the uploaded fixture');

    $check(h18Login($userB, $base, $userBEmail, $password)['status'] === 302 && h18Request($userB, $base, 'GET', '/dashboard')['status'] === 200, 'USER B authenticates in an isolated session');
    $listB = h18Request($userB, $base, 'GET', '/documents');
    $apiListB = h18Request($userB, $base, 'GET', '/api/documents');
    $check($listB['status'] === 200 && !str_contains($listB['body'], $originalName), 'USER B listing excludes Document A');
    $check($apiListB['status'] === 200 && !str_contains($apiListB['body'], $originalName) && !str_contains($apiListB['body'], '"id":' . $documentId), 'USER B API listing excludes Document A');

    $safeForbidden = [$originalName, (string) $document['storage_name'], (string) $document['checksum_sha256'], $fixtureContents, $userAName, $userAEmail, $storedPath];
    $baseline = h18Snapshot($database, $documentId, $storedPath, $storage, $labBefore, $labHistoryBefore);
    $primaryStart = (int) $database->query('SELECT COALESCE(MAX(id),0) FROM security_events')->fetchColumn();
    $crossDetail = h18Request($userB, $base, 'GET', "/documents/{$documentId}");
    $check(h18SafeDenial($crossDetail, $safeForbidden) && h18Snapshot($database, $documentId, $storedPath, $storage, $labBefore, $labHistoryBefore) === $baseline, 'USER B HTML detail denial is safe and causes zero business mutation');
    $crossDownload = h18Request($userB, $base, 'GET', "/documents/{$documentId}/download");
    $check(h18SafeDenial($crossDownload, $safeForbidden) && h18Snapshot($database, $documentId, $storedPath, $storage, $labBefore, $labHistoryBefore) === $baseline, 'USER B download denial is safe and causes zero business mutation');
    $crossApi = h18Request($userB, $base, 'GET', "/api/documents/{$documentId}");
    $crossApiDecoded = json_decode($crossApi['body'], true);
    $check($crossApi['status'] === 404 && ($crossApiDecoded['error']['code'] ?? '') === 'NOT_FOUND' && h18SafeDenial($crossApi, $safeForbidden) && h18Snapshot($database, $documentId, $storedPath, $storage, $labBefore, $labHistoryBefore) === $baseline, 'USER B API detail denial is minimized and causes zero business mutation');
    $bDocuments = h18Request($userB, $base, 'GET', '/documents');
    $validBToken = h18Csrf($bDocuments['body']);
    $crossDelete = h18Request($userB, $base, 'POST', "/documents/{$documentId}/delete", ['_token'=>$validBToken]);
    $check(h18SafeDenial($crossDelete, $safeForbidden) && h18Snapshot($database, $documentId, $storedPath, $storage, $labBefore, $labHistoryBefore) === $baseline, 'USER B valid-CSRF deletion reaches ownership denial and causes zero business mutation');

    $primaryEvents = $database->query("SELECT id,security_session_id,event_type,severity,risk_delta,endpoint,http_method,metadata_json FROM security_events WHERE id>{$primaryStart} AND event_type='OWNERSHIP_ACCESS_DENIED' ORDER BY id")->fetchAll();
    $primarySessionId = count($primaryEvents) === 4 ? (int) $primaryEvents[0]['security_session_id'] : 0;
    $primaryContributors = $primarySessionId > 0 ? $database->query("SELECT id,security_session_id,rule_code,label,risk_delta FROM security_score_contributors WHERE security_session_id={$primarySessionId} AND rule_code='OWNERSHIP_ACCESS_DENIED' ORDER BY id")->fetchAll() : [];
    $primarySession = $primarySessionId > 0 ? $database->query("SELECT threat_score,classification FROM security_sessions WHERE id={$primarySessionId}")->fetch() : false;
    $expectedRequests = [
        ['GET', "/documents/{$documentId}"],
        ['GET', "/documents/{$documentId}/download"],
        ['GET', "/api/documents/{$documentId}"],
        ['POST', "/documents/{$documentId}/delete"],
    ];
    $evidenceValid = count($primaryEvents) === 4 && count($primaryContributors) === 4;
    foreach ($primaryEvents as $index => $event) {
        $metadata = json_decode((string) $event['metadata_json'], true) ?: [];
        $matching = array_filter($primaryContributors, static fn (array $row): bool => str_starts_with((string) $row['label'], 'Event #' . $event['id'] . ':'));
        $evidenceValid = $evidenceValid
            && $event['event_type'] === 'OWNERSHIP_ACCESS_DENIED'
            && $event['severity'] === 'MEDIUM'
            && (int) $event['risk_delta'] === 12
            && $event['http_method'] === $expectedRequests[$index][0]
            && $event['endpoint'] === $expectedRequests[$index][1]
            && ($metadata['category'] ?? null) === 'AUTHORIZATION'
            && ($metadata['outcome'] ?? null) === 'DENIED'
            && ($metadata['target_type'] ?? null) === 'document'
            && ($metadata['target_identifier'] ?? null) === (string) $documentId
            && count($matching) === 1
            && (int) reset($matching)['risk_delta'] === 12
            && (int) reset($matching)['security_session_id'] === (int) $event['security_session_id'];
    }
    $check($evidenceValid, 'Primary four-request workflow creates exactly four matching ownership events and +12 contributors');
    $check(is_array($primarySession) && (int) $primarySession['threat_score'] === 48 && $primarySession['classification'] === 'HIGH', 'Exact local primary ownership contribution is 48 with HIGH classification');
    $csrfSubstitutions = (int) $database->query("SELECT COUNT(*) FROM security_events WHERE id>{$primaryStart} AND event_type='CSRF_REJECTED'")->fetchColumn();
    $check($csrfSubstitutions === 0, 'Valid USER B CSRF reaches ownership enforcement without a CSRF_REJECTED substitute');

    $nonexistentId = (int) $database->query('SELECT COALESCE(MAX(id),0)+100000 FROM documents')->fetchColumn();
    $missingDetail = h18Request($userB, $base, 'GET', "/documents/{$nonexistentId}");
    $missingDownload = h18Request($userB, $base, 'GET', "/documents/{$nonexistentId}/download");
    $missingApi = h18Request($userB, $base, 'GET', "/api/documents/{$nonexistentId}");
    $missingDelete = h18Request($userB, $base, 'POST', "/documents/{$nonexistentId}/delete", ['_token'=>$validBToken]);
    $equivalent = static function (array $left, array $right): bool {
        return $left['status'] === $right['status']
            && trim(preg_replace('/\s+/', ' ', strip_tags($left['body']))) === trim(preg_replace('/\s+/', ' ', strip_tags($right['body'])));
    };
    $check($equivalent($crossDetail, $missingDetail), 'Cross-owner and nonexistent HTML detail responses are equivalent');
    $check($equivalent($crossDownload, $missingDownload), 'Cross-owner and nonexistent download responses are equivalent');
    $check($equivalent($crossApi, $missingApi), 'Cross-owner and nonexistent API detail responses are equivalent');
    $check($equivalent($crossDelete, $missingDelete), 'Cross-owner and nonexistent valid-CSRF delete responses are equivalent');
    $afterEquivalence = h18Snapshot($database, $documentId, $storedPath, $storage, $labBefore, $labHistoryBefore);
    $check($afterEquivalence === $baseline, 'All equivalence probes preserve the complete Document A business-state snapshot');
    $allOwnershipEvents = $database->query("SELECT COUNT(*) FROM security_events WHERE id>{$primaryStart} AND event_type='OWNERSHIP_ACCESS_DENIED'")->fetchColumn();
    $allOwnershipContributors = $database->query("SELECT COUNT(*) FROM security_score_contributors WHERE security_session_id={$primarySessionId} AND rule_code='OWNERSHIP_ACCESS_DENIED'")->fetchColumn();
    $finalBSession = $database->query("SELECT threat_score,classification FROM security_sessions WHERE id={$primarySessionId}")->fetch();
    $check((int) $allOwnershipEvents === 8 && (int) $allOwnershipContributors === 8 && (int) $finalBSession['threat_score'] === 96 && $finalBSession['classification'] === 'CRITICAL', 'Separate equivalence probes accumulate deterministically while remaining bounded and consistently classified');

    $guestDetail = h18Request($guest, $base, 'GET', "/documents/{$documentId}");
    $guestApi = h18Request($guest, $base, 'GET', "/api/documents/{$documentId}");
    $guestDelete = h18Request($guest, $base, 'POST', "/documents/{$documentId}/delete", ['_token'=>'not-a-session-token']);
    $check($guestDetail['status'] === 302 && $guestApi['status'] === 401 && $guestDelete['status'] === 302, 'Authentication precedes ownership and CSRF for unauthenticated document requests');

    $check(h18Login($security, $base, $securityEmail, $password)['status'] === 302, 'Security Admin authenticates only for read-only privacy presentation checks');
    $securityPage = h18Request($security, $base, 'GET', '/security');
    $eventsApi = h18Request($security, $base, 'GET', '/api/security/events');
    $timelineApi = h18Request($security, $base, 'GET', '/api/security/analytics/timeline');
    $eventExport = h18Request($security, $base, 'GET', '/api/security/analytics/export?type=security_events&format=json');
    $sessionExport = h18Request($security, $base, 'GET', '/api/security/analytics/export?type=session_evidence&format=json&session_id=' . $primarySessionId);
    $presentation = $securityPage['body'] . $eventsApi['body'] . $timelineApi['body'] . $eventExport['body'] . $sessionExport['body'];
    $privacyStatuses = [$securityPage['status'],$eventsApi['status'],$timelineApi['status'],$eventExport['status'],$sessionExport['status']];
    $check($privacyStatuses === [200,200,200,200,200], 'Security telemetry, analytics, and evidence privacy surfaces load read-only');
    $check(!preg_match('/source_ip|source_safe_identifier|source_identifier|source_hash|storage_name|checksum_sha256|password_hash|token_hash|authorization_header|csrf_token|session_identifier/i', $presentation), 'Presentation and export boundaries exclude source, storage, credential, CSRF, and session-secret fields');
    $check(!str_contains($presentation, $originalName) && !str_contains($presentation, (string) $document['storage_name']) && !str_contains($presentation, $fixtureContents) && !str_contains($presentation, $userAEmail) && !str_contains($presentation, $userAName), 'Ownership evidence does not expose document content, filename, storage identity, or owner PII');

    $listAAfter = h18Request($userA, $base, 'GET', '/documents');
    $detailAAfter = h18Request($userA, $base, 'GET', "/documents/{$documentId}");
    $downloadAAfter = h18Request($userA, $base, 'GET', "/documents/{$documentId}/download");
    $check($listAAfter['status'] === 200 && str_contains($listAAfter['body'], $originalName) && $detailAAfter['status'] === 200 && hash('sha256', $downloadAAfter['body']) === $fixtureDigest && hash_file('sha256', $storedPath) === $fixtureDigest, 'USER A retains listing, detail, download, byte integrity, and stored integrity after all denials');

    $ownerDenialsBeforeDelete = (int) $database->query("SELECT COUNT(*) FROM security_events WHERE event_type='OWNERSHIP_ACCESS_DENIED' AND id>{$primaryStart}")->fetchColumn();
    $deleteActivityBefore = (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userAId} AND activity_type='DOCUMENT_DELETED'")->fetchColumn();
    $deleteA = h18Request($userA, $base, 'POST', "/documents/{$documentId}/delete", ['_token'=>h18Csrf($detailAAfter['body'])]);
    clearstatcache(true, $storedPath);
    $ownerDenialsAfterDelete = (int) $database->query("SELECT COUNT(*) FROM security_events WHERE event_type='OWNERSHIP_ACCESS_DENIED' AND id>{$primaryStart}")->fetchColumn();
    $deleteActivityAfter = (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userAId} AND activity_type='DOCUMENT_DELETED'")->fetchColumn();
    $check($deleteA['status'] === 302 && (int) $database->query("SELECT COUNT(*) FROM documents WHERE id={$documentId}")->fetchColumn() === 0 && !is_file($storedPath), 'Legitimate USER A valid-CSRF deletion removes the active row and private file');
    $check($deleteActivityAfter === $deleteActivityBefore + 1 && $ownerDenialsAfterDelete === $ownerDenialsBeforeDelete && h18Files($storage, '.trash') === $trashBefore, 'Legitimate deletion records its activity, creates no ownership denial, and leaves no trash fixture');
    $labAfter = (string) $database->query("SELECT COALESCE(GROUP_CONCAT(CONCAT(id,':',state,':',is_active) ORDER BY id SEPARATOR ','),'') FROM vulnerability_modules")->fetchColumn();
    $labHistoryAfter = (int) $database->query('SELECT COUNT(*) FROM vulnerability_state_changes')->fetchColumn();
    $check($labAfter === $labBefore && $labHistoryAfter === $labHistoryBefore && h18Request($guest, $base, 'GET', '/lab/idor')['status'] === 404, 'LAB state remains unchanged, isolated, and disabled');
} catch (Throwable $exception) {
    $failed++;
    echo '[FAIL] H18 HTTP/E2E exception: ' . $exception->getMessage() . PHP_EOL;
} finally {
    foreach ($clients as $client) {
        if ($client instanceof CurlHandle) curl_close($client);
    }
    if (is_resource($server)) {
        proc_terminate($server);
        proc_close($server);
    }
    if (is_file($temporaryFile)) @unlink($temporaryFile);
    foreach (h18Files($storage) as $name) {
        if (!in_array($name, $storageBefore, true)) @unlink($storage . DIRECTORY_SEPARATOR . $name);
    }
    foreach (h18Files($storage, '.trash') as $name) {
        if (!in_array($name, $trashBefore, true)) @unlink($storage . DIRECTORY_SEPARATOR . '.trash' . DIRECTORY_SEPARATOR . $name);
    }
    $database->exec("DELETE FROM security_score_contributors WHERE id>{$starts['security_score_contributors']}");
    $database->exec("DELETE FROM security_events WHERE id>{$starts['security_events']}");
    $database->exec("DELETE FROM security_sessions WHERE id>{$starts['security_sessions']}");
    $database->exec("DELETE FROM documents WHERE id>{$starts['documents']}");
    $database->exec("DELETE FROM user_activity WHERE id>{$starts['user_activity']}");
    $database->exec("DELETE FROM users WHERE id>{$starts['users']}");
}

$residual = 0;
foreach ($trackedTables as $table) {
    $residual += (int) $database->query("SELECT COUNT(*) FROM {$table} WHERE id>{$starts[$table]}")->fetchColumn();
}
$storageClean = h18Files($storage) === $storageBefore && h18Files($storage, '.trash') === $trashBefore;
$check($residual === 0 && $storageClean, 'H18 HTTP removes exact database, active-file, and trash fixtures');
echo 'Cleanup: ' . ($residual === 0 && $storageClean ? 'PASS' : 'FAIL') . PHP_EOL;
echo PHP_EOL . "{$passed} H18 HTTP/E2E ownership checks passed, {$failed} failed, 0 skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
