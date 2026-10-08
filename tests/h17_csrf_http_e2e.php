<?php

declare(strict_types=1);

use App\Core\Env;

$root = dirname(__DIR__);
require $root . '/app/Core/Env.php';
Env::load($root . '/.env');

if ((string) getenv('TEST_DB_DATABASE') !== 'chimera_test' || (string) getenv('DB_DATABASE') !== 'chimera' || (string) getenv('DB_PORT') !== '3308') {
    echo "[FAIL] H17 HTTP database guards are not configured safely." . PHP_EOL;
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
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
);
$connection = $database->query('SELECT DATABASE() database_name,@@port server_port,CURRENT_USER() authenticated_user')->fetch();
if ($connection['database_name'] !== 'chimera_test' || (int) $connection['server_port'] !== 3308 || !str_starts_with($connection['authenticated_user'], 'chimera_test_app@')) {
    echo "[FAIL] Unsafe H17 HTTP target." . PHP_EOL;
    exit(1);
}

$trackedTables = ['users','documents','user_activity','security_events','security_sessions','security_score_contributors','vulnerability_modules','vulnerability_state_changes'];
$starts = [];
foreach ($trackedTables as $table) {
    $starts[$table] = (int) $database->query("SELECT COALESCE(MAX(id),0) FROM {$table}")->fetchColumn();
}

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};

function h17Client(): CurlHandle
{
    $client = curl_init();
    curl_setopt($client, CURLOPT_COOKIEFILE, '');
    curl_setopt($client, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($client, CURLOPT_HEADER, true);
    curl_setopt($client, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($client, CURLOPT_TIMEOUT, 10);
    return $client;
}

function h17Request(CurlHandle $client, string $base, string $method, string $path, array|string|null $fields = null): array
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
        throw new RuntimeException('H17 local HTTP request failed.');
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
    return ['status' => (int) curl_getinfo($client, CURLINFO_RESPONSE_CODE), 'headers' => $headers, 'body' => substr($raw, $headerSize)];
}

function h17Csrf(string $html): string
{
    if (!preg_match('/name="_token"\s+value="([^"]+)"/', $html, $matches)) {
        throw new RuntimeException('Expected CSRF field was not rendered.');
    }
    return html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function h17Login(CurlHandle $client, string $base, string $email, string $password): array
{
    $page = h17Request($client, $base, 'GET', '/login');
    return h17Request($client, $base, 'POST', '/login', ['_token' => h17Csrf($page['body']), 'email' => $email, 'password' => $password]);
}

function h17StoredFiles(string $root): array
{
    $files = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $entry) {
        if ($entry->isFile()) {
            $files[] = str_replace('\\', '/', substr($entry->getPathname(), strlen($root) + 1));
        }
    }
    sort($files);
    return $files;
}

$suffix = bin2hex(random_bytes(6));
$sentinel = 'H17_INVALID_TOKEN_SENTINEL_' . strtoupper($suffix);
$userEmail = "h17-user-{$suffix}@e2e.chimera.test";
$adminEmail = "h17-admin-{$suffix}@e2e.chimera.test";
$securityEmail = "h17-security-{$suffix}@e2e.chimera.test";
$password = 'H17-Synthetic!2026';
$clients = [];
$server = null;
$temporaryFile = tempnam(sys_get_temp_dir(), 'chimera-h17-');
file_put_contents($temporaryFile, "H17 synthetic document fixture.\n");
$storage = $root . '/storage/uploads/h17-e2e-documents';
if (!is_dir($storage) && !mkdir($storage, 0750, true) && !is_dir($storage)) {
    echo "[FAIL] H17 isolated storage could not be created." . PHP_EOL;
    exit(1);
}
$storage = realpath($storage) ?: $storage;
$storageBefore = h17StoredFiles($storage);
$log = $root . '/storage/logs/h17-e2e-server.log';

try {
    $insertUser = $database->prepare('INSERT INTO users(name,email,password_hash,role,is_active) VALUES(?,?,?,?,1)');
    $insertUser->execute(['H17 Admin', $adminEmail, password_hash($password, PASSWORD_DEFAULT), 'admin']);
    $adminId = (int) $database->lastInsertId();
    $insertUser->execute(['H17 Security Admin', $securityEmail, password_hash($password, PASSWORD_DEFAULT), 'security_admin']);
    $securityId = (int) $database->lastInsertId();
    $insertModule = $database->prepare('INSERT INTO vulnerability_modules(vulnerability_identifier,name,description,affected_component,expected_attack_surface,learning_objective,expected_impact,mitigation,state,is_active) VALUES(?,?,?,?,?,?,?,?,?,1)');
    $insertModule->execute(['CHIM-VULN-001','H17 guarded IDOR module','Synthetic local fixture','/lab/idor','Synthetic objects only','CSRF state control','Synthetic-only impact','Ownership and CSRF controls','VULNERABLE']);
    $moduleId = (int) $database->lastInsertId();

    $socket = stream_socket_server('tcp://127.0.0.1:0', $socketError, $socketMessage);
    if (!is_resource($socket)) {
        throw new RuntimeException('Could not allocate H17 local server port.');
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
        [0 => ['pipe','r'], 1 => ['file',$log,'a'], 2 => ['file',$log,'a']],
        $pipes,
        $root,
        $environment
    );
    if (!is_resource($server)) {
        throw new RuntimeException('Could not start H17 local server.');
    }
    fclose($pipes[0]);
    $ready = false;
    for ($attempt = 0; $attempt < 30; $attempt++) {
        $probe = h17Client();
        try {
            $ready = h17Request($probe, $base, 'GET', '/')['status'] === 200;
        } catch (Throwable) {
            $ready = false;
        }
        curl_close($probe);
        if ($ready) break;
        usleep(100000);
    }
    if (!$ready) throw new RuntimeException('H17 local server did not become ready.');

    $guest = h17Client();
    $user = h17Client();
    $admin = h17Client();
    $security = h17Client();
    array_push($clients, $guest, $user, $admin, $security);

    $registrationActivityBefore = (int) $database->query('SELECT COUNT(*) FROM user_activity')->fetchColumn();
    $missingRegister = h17Request($user, $base, 'POST', '/register', ['name'=>'Rejected User','email'=>$userEmail,'password'=>$password,'password_confirmation'=>$password]);
    $check($missingRegister['status'] === 419 && (int) $database->query('SELECT COUNT(*) FROM users WHERE email=' . $database->quote($userEmail))->fetchColumn() === 0 && (int) $database->query('SELECT COUNT(*) FROM user_activity')->fetchColumn() === $registrationActivityBefore, 'Rejected registration returns 419 and creates no user or activity');

    $registerPage = h17Request($user, $base, 'GET', '/register');
    $registrationToken = h17Csrf($registerPage['body']);
    $register = h17Request($user, $base, 'POST', '/register', ['_token'=>$registrationToken,'name'=>'H17 User','email'=>$userEmail,'password'=>$password,'password_confirmation'=>$password]);
    $userId = (int) $database->query('SELECT id FROM users WHERE email=' . $database->quote($userEmail))->fetchColumn();
    $check($register['status'] === 302 && $userId > 0 && h17Request($user, $base, 'GET', '/dashboard')['status'] === 200, 'Valid registration establishes an authenticated USER session');

    $dashboard = h17Request($user, $base, 'GET', '/dashboard');
    $preLogoutToken = h17Csrf($dashboard['body']);
    $logout = h17Request($user, $base, 'POST', '/logout', ['_token'=>$preLogoutToken]);
    $check($logout['status'] === 302 && h17Request($user, $base, 'GET', '/dashboard')['status'] === 302, 'Valid logout invalidates the initial authenticated session');

    $loginActivityBefore = (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userId} AND activity_type='LOGIN'")->fetchColumn();
    $invalidLogin = h17Request($user, $base, 'POST', '/login', ['_token'=>$sentinel,'email'=>$userEmail,'password'=>$password]);
    $lastLogin = $database->query("SELECT last_login_at FROM users WHERE id={$userId}")->fetchColumn();
    $check($invalidLogin['status'] === 419 && $lastLogin === null && (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userId} AND activity_type='LOGIN'")->fetchColumn() === $loginActivityBefore && h17Request($user, $base, 'GET', '/dashboard')['status'] === 302, 'Incorrect-token login causes no authentication, last-login, or success-activity mutation');
    $staleLogin = h17Request($user, $base, 'POST', '/login', ['_token'=>$preLogoutToken,'email'=>$userEmail,'password'=>$password]);
    $check($staleLogin['status'] === 419, 'Token from the invalidated session is rejected as stale');
    $validLogin = h17Login($user, $base, $userEmail, $password);
    $check($validLogin['status'] === 302 && h17Request($user, $base, 'GET', '/dashboard')['status'] === 200, 'Valid CSRF login remains functional');

    $missingLogout = h17Request($user, $base, 'POST', '/logout', []);
    $check($missingLogout['status'] === 419 && h17Request($user, $base, 'GET', '/dashboard')['status'] === 200, 'Rejected logout returns 419 and leaves the authenticated session intact');

    $nameBefore = (string) $database->query("SELECT name FROM users WHERE id={$userId}")->fetchColumn();
    $profileActivityBefore = (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userId} AND activity_type='PROFILE_UPDATED'")->fetchColumn();
    clearstatcache(true, $log);
    $logSize = is_file($log) ? (int) filesize($log) : 0;
    $malformedProfile = h17Request($user, $base, 'POST', '/profile', '_token%5B0%5D=' . rawurlencode($sentinel) . '&name=Rejected+Mutation');
    clearstatcache(true, $log);
    $logContents = is_file($log) ? (string) file_get_contents($log) : '';
    $newLog = substr($logContents, $logSize);
    $safeMalformedBody = !preg_match('/Array to string conversion|Warning:|Stack trace|[A-Za-z]:\\\\/i', $malformedProfile['body']);
    $check($malformedProfile['status'] === 419 && $safeMalformedBody && !str_contains($newLog, 'Array to string conversion'), 'Array-valued token returns safe 419 with no warning, stack trace, path disclosure, or HTTP 500');
    $check((string) $database->query("SELECT name FROM users WHERE id={$userId}")->fetchColumn() === $nameBefore && (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userId} AND activity_type='PROFILE_UPDATED'")->fetchColumn() === $profileActivityBefore, 'Rejected profile update leaves profile and activity unchanged');
    $profilePage = h17Request($user, $base, 'GET', '/profile');
    $validProfile = h17Request($user, $base, 'POST', '/profile', ['_token'=>h17Csrf($profilePage['body']),'name'=>'H17 User Verified']);
    $check($validProfile['status'] === 302 && (string) $database->query("SELECT name FROM users WHERE id={$userId}")->fetchColumn() === 'H17 User Verified', 'Valid CSRF profile update remains functional');

    $documentsBefore = (int) $database->query("SELECT COUNT(*) FROM documents WHERE user_id={$userId}")->fetchColumn();
    $uploadActivityBefore = (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userId} AND activity_type='DOCUMENT_UPLOADED'")->fetchColumn();
    $invalidUpload = h17Request($user, $base, 'POST', '/documents', ['_token'=>$sentinel,'document'=>new CURLFile($temporaryFile,'text/plain','h17.txt')]);
    $storageAfterRejectedUpload = h17StoredFiles($storage);
    $check($invalidUpload['status'] === 419 && (int) $database->query("SELECT COUNT(*) FROM documents WHERE user_id={$userId}")->fetchColumn() === $documentsBefore && (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userId} AND activity_type='DOCUMENT_UPLOADED'")->fetchColumn() === $uploadActivityBefore && $storageAfterRejectedUpload === $storageBefore, 'Rejected upload creates no document, private file, or upload activity');
    $documentsPage = h17Request($user, $base, 'GET', '/documents');
    $validUpload = h17Request($user, $base, 'POST', '/documents', ['_token'=>h17Csrf($documentsPage['body']),'document'=>new CURLFile($temporaryFile,'text/plain','h17.txt')]);
    $document = $database->query("SELECT * FROM documents WHERE user_id={$userId} ORDER BY id DESC LIMIT 1")->fetch();
    $storedFile = $storage . DIRECTORY_SEPARATOR . $document['storage_name'];
    $check($validUpload['status'] === 302 && is_file($storedFile), 'Valid CSRF document upload remains functional');

    $deleteActivityBefore = (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userId} AND activity_type='DOCUMENT_DELETED'")->fetchColumn();
    $missingDelete = h17Request($user, $base, 'POST', '/documents/' . $document['id'] . '/delete', []);
    $check($missingDelete['status'] === 419 && (int) $database->query('SELECT COUNT(*) FROM documents WHERE id=' . (int) $document['id'])->fetchColumn() === 1 && is_file($storedFile) && (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userId} AND activity_type='DOCUMENT_DELETED'")->fetchColumn() === $deleteActivityBefore, 'Rejected deletion preserves document row, private file, and delete activity count');
    $deletePage = h17Request($user, $base, 'GET', '/documents/' . $document['id']);
    $validDelete = h17Request($user, $base, 'POST', '/documents/' . $document['id'] . '/delete', ['_token'=>h17Csrf($deletePage['body'])]);
    clearstatcache(true, $storedFile);
    $check($validDelete['status'] === 302 && !is_file($storedFile) && (int) $database->query('SELECT COUNT(*) FROM documents WHERE id=' . (int) $document['id'])->fetchColumn() === 0, 'Valid CSRF document deletion remains functional');

    $guestProtected = h17Request($guest, $base, 'POST', '/profile', ['_token'=>$sentinel,'name'=>'Never']);
    $userLabDenied = h17Request($user, $base, 'POST', '/security/lab/modules/' . $moduleId . '/state', ['_token'=>$sentinel,'state'=>'REMEDIATED']);
    $check($guestProtected['status'] === 302 && ($guestProtected['headers']['location'] ?? '') === $base . '/login', 'Guest protected POST is stopped by authentication before CSRF');
    $check($userLabDenied['status'] === 403, 'USER is stopped by role authorization before Security Admin CSRF processing');

    $check(h17Login($admin, $base, $adminEmail, $password)['status'] === 302, 'ADMIN authentication succeeds for precedence testing');
    $adminLabDenied = h17Request($admin, $base, 'POST', '/security/lab/modules/' . $moduleId . '/state', ['_token'=>$sentinel,'state'=>'REMEDIATED']);
    $check($adminLabDenied['status'] === 403, 'ADMIN is stopped by role authorization before Security Admin CSRF processing');

    $check(h17Login($security, $base, $securityEmail, $password)['status'] === 302, 'Security Admin authentication succeeds for guarded state-control testing');
    $moduleStateBefore = (string) $database->query("SELECT state FROM vulnerability_modules WHERE id={$moduleId}")->fetchColumn();
    $historyBefore = (int) $database->query("SELECT COUNT(*) FROM vulnerability_state_changes WHERE vulnerability_module_id={$moduleId}")->fetchColumn();
    $invalidLab = h17Request($security, $base, 'POST', '/security/lab/modules/' . $moduleId . '/state', ['_token'=>$sentinel,'state'=>'REMEDIATED']);
    $check($invalidLab['status'] === 419 && (string) $database->query("SELECT state FROM vulnerability_modules WHERE id={$moduleId}")->fetchColumn() === $moduleStateBefore && (int) $database->query("SELECT COUNT(*) FROM vulnerability_state_changes WHERE vulnerability_module_id={$moduleId}")->fetchColumn() === $historyBefore, 'Rejected Security Admin request preserves module state and history');
    $labManagement = h17Request($security, $base, 'GET', '/security/lab');
    $validLab = h17Request($security, $base, 'POST', '/security/lab/modules/' . $moduleId . '/state', ['_token'=>h17Csrf($labManagement['body']),'state'=>'REMEDIATED']);
    $labDisabled = h17Request($guest, $base, 'GET', '/lab/sqli');
    $check($validLab['status'] === 302 && (string) $database->query("SELECT state FROM vulnerability_modules WHERE id={$moduleId}")->fetchColumn() === 'REMEDIATED' && $labDisabled['status'] === 404, 'Valid guarded module control works while the vulnerability LAB remains globally disabled');

    $csrfEvents = $database->query("SELECT id,event_type,severity,risk_delta,metadata_json,security_session_id FROM security_events WHERE id>{$starts['security_events']} AND event_type='CSRF_REJECTED' ORDER BY id")->fetchAll();
    $csrfContributors = $database->query("SELECT id,rule_code,label,risk_delta,security_session_id FROM security_score_contributors WHERE id>{$starts['security_score_contributors']} AND rule_code='CSRF_REJECTED' ORDER BY id")->fetchAll();
    $check(count($csrfEvents) === 8, 'Seven-route negative coverage plus one stale-token check produced exactly eight CSRF_REJECTED events');
    $check(count($csrfContributors) === 8 && array_sum(array_map(static fn (array $row): int => (int) $row['risk_delta'], $csrfContributors)) === 96, 'Exactly eight CSRF contributors were created for a total deterministic contribution of 96');
    $eventConsistency = true;
    foreach ($csrfEvents as $event) {
        $metadata = json_decode((string) $event['metadata_json'], true) ?: [];
        $matching = array_filter($csrfContributors, static fn (array $row): bool => str_starts_with((string) $row['label'], 'Event #' . $event['id'] . ':'));
        $eventConsistency = $eventConsistency && $event['severity'] === 'MEDIUM' && (int) $event['risk_delta'] === 12 && ($metadata['category'] ?? null) === 'REQUEST_SECURITY' && ($metadata['outcome'] ?? null) === 'REJECTED' && count($matching) === 1 && (int) reset($matching)['risk_delta'] === 12 && (int) reset($matching)['security_session_id'] === (int) $event['security_session_id'];
    }
    $check($eventConsistency, 'Every rejection has exact taxonomy, one +12 contributor, and matching event/session correlation');
    $invalidScores = (int) $database->query("SELECT COUNT(*) FROM security_sessions WHERE id>{$starts['security_sessions']} AND (threat_score<0 OR threat_score>100 OR classification<>(CASE WHEN threat_score>=75 THEN 'CRITICAL' WHEN threat_score>=45 THEN 'HIGH' WHEN threat_score>=20 THEN 'MEDIUM' ELSE 'LOW' END))")->fetchColumn();
    $check($invalidScores === 0, 'All H17 security-session scores remain bounded and consistently classified');

    $metadataText = (string) $database->query("SELECT GROUP_CONCAT(COALESCE(metadata_json,'') SEPARATOR '\n') FROM security_events WHERE id>{$starts['security_events']} AND event_type='CSRF_REJECTED'")->fetchColumn();
    $contributorText = (string) $database->query("SELECT GROUP_CONCAT(label SEPARATOR '\n') FROM security_score_contributors WHERE id>{$starts['security_score_contributors']} AND rule_code='CSRF_REJECTED'")->fetchColumn();
    $securityPage = h17Request($security, $base, 'GET', '/security');
    $eventsApi = h17Request($security, $base, 'GET', '/api/security/events');
    $timelineApi = h17Request($security, $base, 'GET', '/api/security/analytics/timeline');
    $eventExport = h17Request($security, $base, 'GET', '/api/security/analytics/export?type=security_events&format=json');
    $sessionExport = h17Request($security, $base, 'GET', '/api/security/analytics/export?type=session_evidence&format=json');
    $presentation = $metadataText . $contributorText . $securityPage['body'] . $eventsApi['body'] . $timelineApi['body'] . $eventExport['body'] . $sessionExport['body'];
    $check(!str_contains($presentation, $sentinel), 'Invalid-token sentinel is absent from persistence, dashboards, APIs, analytics, and evidence exports');
    $check(!preg_match('/source_ip|source_safe_identifier|source_identifier|source_hash|password_hash|token_hash|authorization_header|session_identifier|csrf_token/i', $securityPage['body'] . $eventsApi['body'] . $timelineApi['body'] . $eventExport['body'] . $sessionExport['body']), 'H13-H16 source, credential, session-secret, and CSRF privacy boundaries remain intact');

    $finalDashboard = h17Request($user, $base, 'GET', '/dashboard');
    $finalLogout = h17Request($user, $base, 'POST', '/logout', ['_token'=>h17Csrf($finalDashboard['body'])]);
    $check($finalLogout['status'] === 302 && h17Request($user, $base, 'GET', '/dashboard')['status'] === 302, 'Final valid logout remains functional and invalidates the session');
} catch (Throwable $exception) {
    $failed++;
    echo '[FAIL] H17 HTTP E2E exception: ' . $exception->getMessage() . PHP_EOL;
} finally {
    foreach ($clients as $client) if ($client instanceof CurlHandle) curl_close($client);
    if (is_resource($server)) {
        proc_terminate($server);
        proc_close($server);
    }
    if (is_file($temporaryFile)) @unlink($temporaryFile);
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($storage, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $entry) {
        $relative = str_replace('\\', '/', substr($entry->getPathname(), strlen($storage) + 1));
        if ($entry->isFile() && !in_array($relative, $storageBefore, true)) @unlink($entry->getPathname());
    }
    $database->exec("DELETE FROM security_score_contributors WHERE id>{$starts['security_score_contributors']}");
    $database->exec("DELETE FROM security_events WHERE id>{$starts['security_events']}");
    $database->exec("DELETE FROM security_sessions WHERE id>{$starts['security_sessions']}");
    $database->exec("DELETE FROM vulnerability_state_changes WHERE id>{$starts['vulnerability_state_changes']}");
    $database->exec("DELETE FROM vulnerability_modules WHERE id>{$starts['vulnerability_modules']}");
    $database->exec("DELETE FROM documents WHERE id>{$starts['documents']}");
    $database->exec("DELETE FROM user_activity WHERE id>{$starts['user_activity']}");
    $database->exec("DELETE FROM users WHERE id>{$starts['users']}");
}

$residual = 0;
foreach ($trackedTables as $table) {
    $residual += (int) $database->query("SELECT COUNT(*) FROM {$table} WHERE id>{$starts[$table]}")->fetchColumn();
}
$storageAfter = h17StoredFiles($storage);
$check($residual === 0 && $storageAfter === $storageBefore, 'H17 HTTP removes exact database and private-file fixtures');
echo 'Cleanup: ' . ($residual === 0 && $storageAfter === $storageBefore ? 'PASS' : 'FAIL') . PHP_EOL;
echo PHP_EOL . "{$passed} H17 HTTP/E2E CSRF checks passed, {$failed} failed, 0 skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
