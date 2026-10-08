<?php

declare(strict_types=1);

use App\Core\Env;

$root = dirname(__DIR__);
require $root . '/app/Core/Env.php';
Env::load($root . '/.env');

if ((string) getenv('TEST_DB_DATABASE') !== 'chimera_test' || (string) getenv('DB_DATABASE') !== 'chimera' || (string) getenv('DB_PORT') !== '3308') {
    echo "[FAIL] H19 HTTP database guards are not configured safely." . PHP_EOL;
    exit(1);
}
$testUser = (string) getenv('TEST_DB_USERNAME');
$testPassword = (string) getenv('TEST_DB_PASSWORD');
if ($testUser === '' || $testPassword === '') {
    echo "[FAIL] Dedicated chimera_test credentials are required." . PHP_EOL;
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
    echo "[FAIL] Unsafe H19 HTTP target." . PHP_EOL;
    exit(1);
}

$trackedTables = ['users','documents','user_activity','security_events','security_sessions','security_score_contributors','honeytoken_events'];
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

function h19Client(): CurlHandle
{
    $client = curl_init();
    curl_setopt($client, CURLOPT_COOKIEFILE, '');
    curl_setopt($client, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($client, CURLOPT_HEADER, true);
    curl_setopt($client, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($client, CURLOPT_TIMEOUT, 10);
    return $client;
}

function h19Request(CurlHandle $client, string $base, string $method, string $path, array|string|null $fields = null): array
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
        throw new RuntimeException('H19 local HTTP request failed.');
    }
    $headerSize = curl_getinfo($client, CURLINFO_HEADER_SIZE);
    return ['status'=>(int) curl_getinfo($client, CURLINFO_RESPONSE_CODE), 'body'=>substr($raw, $headerSize)];
}

function h19Csrf(string $html): string
{
    if (!preg_match('/name="_token"\s+value="([^"]+)"/', $html, $matches)) {
        throw new RuntimeException('Expected CSRF field was not rendered.');
    }
    return html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function h19Files(string $root, string $subdirectory = ''): array
{
    $directory = $subdirectory === '' ? $root : $root . DIRECTORY_SEPARATOR . $subdirectory;
    if (!is_dir($directory)) return [];
    $files = [];
    foreach (new DirectoryIterator($directory) as $entry) {
        if ($entry->isFile()) $files[] = $entry->getFilename();
    }
    sort($files);
    return $files;
}

$suffix = bin2hex(random_bytes(6));
$email = "h19-owner-{$suffix}@e2e.chimera.test";
$password = 'H19-Synthetic!2026';
$originalName = "h19-private-{$suffix}.txt";
$sentinel = "H19-PRIVATE-SENTINEL-{$suffix}";
$fixtureContents = $sentinel . "\nHarmless local storage-denial fixture.\n";
$temporaryFile = tempnam(sys_get_temp_dir(), 'chimera-h19-');
file_put_contents($temporaryFile, $fixtureContents);
$fixtureDigest = hash('sha256', $fixtureContents);
$storage = $root . '/storage/uploads/h19-e2e-documents';
if (!is_dir($storage) && !mkdir($storage, 0750, true) && !is_dir($storage)) {
    echo "[FAIL] H19 isolated HTTP storage could not be created." . PHP_EOL;
    exit(1);
}
$storage = realpath($storage) ?: $storage;
$storageBefore = h19Files($storage);
$trashBefore = h19Files($storage, '.trash');
$log = $root . '/storage/logs/h19-e2e-server.log';
$client = null;
$guest = null;
$server = null;

try {
    $insertUser = $database->prepare('INSERT INTO users(name,email,password_hash,role,is_active) VALUES(?,?,?,?,1)');
    $insertUser->execute(['H19 Storage Owner', $email, password_hash($password, PASSWORD_DEFAULT), 'user']);
    $userId = (int) $database->lastInsertId();

    $socket = stream_socket_server('tcp://127.0.0.1:0', $socketError, $socketMessage);
    if (!is_resource($socket)) throw new RuntimeException('Could not allocate H19 local server port.');
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
    if (!is_resource($server)) throw new RuntimeException('Could not start H19 local server.');
    fclose($pipes[0]);
    $ready = false;
    for ($attempt = 0; $attempt < 30; $attempt++) {
        $probe = h19Client();
        try { $ready = h19Request($probe, $base, 'GET', '/')['status'] === 200; } catch (Throwable) { $ready = false; }
        curl_close($probe);
        if ($ready) break;
        usleep(100000);
    }
    if (!$ready) throw new RuntimeException('H19 local server did not become ready.');

    $client = h19Client();
    $guest = h19Client();
    $loginPage = h19Request($client, $base, 'GET', '/login');
    $login = h19Request($client, $base, 'POST', '/login', ['_token'=>h19Csrf($loginPage['body']), 'email'=>$email, 'password'=>$password]);
    $check($login['status'] === 302 && h19Request($client, $base, 'GET', '/dashboard')['status'] === 200, 'Synthetic standard USER authenticates through the local application');

    $documentsPage = h19Request($client, $base, 'GET', '/documents');
    $upload = h19Request($client, $base, 'POST', '/documents', ['_token'=>h19Csrf($documentsPage['body']), 'document'=>new CURLFile($temporaryFile, 'text/plain', $originalName)]);
    $statement = $database->prepare('SELECT * FROM documents WHERE user_id=:user_id ORDER BY id DESC LIMIT 1');
    $statement->execute(['user_id'=>$userId]);
    $document = $statement->fetch();
    if (!is_array($document)) throw new RuntimeException('Owner upload did not create the H19 document.');
    $documentId = (int) $document['id'];
    $storageName = (string) $document['storage_name'];
    $storedPath = $storage . DIRECTORY_SEPARATOR . $storageName;
    $check($upload['status'] === 302 && is_file($storedPath) && hash_file('sha256', $storedPath) === $fixtureDigest, 'Valid-CSRF owner upload creates the byte-identical private fixture');

    $listing = h19Request($client, $base, 'GET', '/documents');
    $detail = h19Request($client, $base, 'GET', "/documents/{$documentId}");
    $apiList = h19Request($client, $base, 'GET', '/api/documents');
    $apiDetail = h19Request($client, $base, 'GET', "/api/documents/{$documentId}");
    $download = h19Request($client, $base, 'GET', "/documents/{$documentId}/download");
    $applicationPresentation = $listing['body'] . $detail['body'] . $apiList['body'] . $apiDetail['body'];
    $check($listing['status'] === 200 && str_contains($listing['body'], $originalName) && $detail['status'] === 200, 'Owner listing and detail expose only the intended application metadata');
    $check($download['status'] === 200 && hash('sha256', $download['body']) === $fixtureDigest, 'Application-controlled owner download is byte-identical');
    $check(!str_contains($applicationPresentation, $storageName) && !str_contains($applicationPresentation, $storedPath) && !preg_match('~(?:href|src)=["\'][^"\']*/storage/~i', $applicationPresentation), 'HTML and document APIs emit no storage name, private path, or direct storage URL');

    $eventsBeforeDirect = (int) $database->query('SELECT COALESCE(MAX(id),0) FROM security_events')->fetchColumn();
    $direct = h19Request($guest, $base, 'GET', '/storage/uploads/documents/' . rawurlencode($storageName));
    $eventsAfterDirect = (int) $database->query('SELECT COALESCE(MAX(id),0) FROM security_events')->fetchColumn();
    $unsafeDisclosure = str_contains($direct['body'], $sentinel)
        || str_contains($direct['body'], $storageName)
        || str_contains($direct['body'], $storedPath)
        || preg_match('/stack trace|php warning|password_hash|source_safe_identifier|source_identifier|source_hash|authorization_header|csrf|session[_ -]?id|cookie/i', $direct['body']);
    $check($direct['status'] === 404 && !$unsafeDisclosure, 'Local public-root direct path returns a safe CHIMERA 404 with no private content or error disclosure');
    $check($eventsAfterDirect === $eventsBeforeDirect, 'Local direct-path 404 creates no application telemetry or score side effect');
    echo '[INFO] Local direct-path result uses the PHP development-server CHIMERA router and is NOT proof of InfinityFree Apache/.htaccess enforcement.' . PHP_EOL;

    $downloadAfter = h19Request($client, $base, 'GET', "/documents/{$documentId}/download");
    $check($downloadAfter['status'] === 200 && hash('sha256', $downloadAfter['body']) === $fixtureDigest && hash_file('sha256', $storedPath) === $fixtureDigest, 'Owner download and stored integrity remain intact after the local direct-path request');

    $positiveEvents = $database->query("SELECT event_type,risk_delta,metadata_json FROM security_events WHERE id>{$starts['security_events']} ORDER BY id")->fetchAll();
    $normalEventsSafe = true;
    foreach ($positiveEvents as $event) {
        $normalEventsSafe = $normalEventsSafe
            && (int) $event['risk_delta'] === 0
            && !preg_match('/source_ip|csrf|cookie|authorization|password|storage_name|source_safe_identifier/i', (string) $event['metadata_json']);
    }
    $check($normalEventsSafe && (int) $database->query("SELECT COUNT(*) FROM security_score_contributors WHERE id>{$starts['security_score_contributors']}")->fetchColumn() === 0, 'Normal owner workflow telemetry remains zero-weight, sanitized, and contributor-free');
    $deceptionCount = (int) $database->query("SELECT COUNT(*) FROM security_events WHERE id>{$starts['security_events']} AND event_type IN ('DECOY_ACCESSED','HONEYTOKEN_TRIGGERED','ADAPTIVE_PROFILE_SELECTED','ADAPTIVE_DECEPTION_RENDERED')")->fetchColumn();
    $check($deceptionCount === 0 && (int) $database->query("SELECT COUNT(*) FROM honeytoken_events WHERE id>{$starts['honeytoken_events']}")->fetchColumn() === 0, 'No deception, adaptive, or honeytoken interaction is introduced');

    $delete = h19Request($client, $base, 'POST', "/documents/{$documentId}/delete", ['_token'=>h19Csrf($detail['body'])]);
    clearstatcache(true, $storedPath);
    $listingAfter = h19Request($client, $base, 'GET', '/documents');
    $check($delete['status'] === 302 && (int) $database->query("SELECT COUNT(*) FROM documents WHERE id={$documentId}")->fetchColumn() === 0 && !is_file($storedPath) && !str_contains($listingAfter['body'], $originalName), 'Valid-CSRF owner deletion removes the row, active fixture, and listing entry');
    $check(h19Files($storage, '.trash') === $trashBefore, 'Normal HTTP deletion leaves no H19 trash fixture');
    $labAfter = (string) $database->query("SELECT COALESCE(GROUP_CONCAT(CONCAT(id,':',state,':',is_active) ORDER BY id SEPARATOR ','),'') FROM vulnerability_modules")->fetchColumn();
    $labHistoryAfter = (int) $database->query('SELECT COUNT(*) FROM vulnerability_state_changes')->fetchColumn();
    $check($labAfter === $labBefore && $labHistoryAfter === $labHistoryBefore && h19Request($guest, $base, 'GET', '/lab/idor')['status'] === 404, 'LAB remains unchanged, isolated, and disabled');

    $documentController = (string) file_get_contents($root . '/app/Controllers/DocumentController.php');
    $routesSource = (string) file_get_contents($root . '/routes/web.php');
    $analyticsSource = (string) file_get_contents($root . '/app/Services/SecurityAnalyticsService.php');
    $check(str_contains($documentController, 'Document::findOwned') && preg_match("~post\('/documents/\{id\}/delete'.+Authenticate::class, VerifyCsrf::class~", $routesSource) === 1, 'H18 owner scoping and H17 route-level CSRF enforcement remain wired to document operations');
    $check(preg_match('/MAX_EXPORT\s*=\s*1000/', $analyticsSource) === 1 && !preg_match('/\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|REPLACE\s+INTO|ALTER\s+TABLE|DROP\s+TABLE|TRUNCATE\s+TABLE)\b/i', $analyticsSource), 'H16 analytics export bound remains present without a state-changing analytics query');
} catch (Throwable $exception) {
    $failed++;
    echo '[FAIL] H19 HTTP/E2E exception: ' . $exception->getMessage() . PHP_EOL;
} finally {
    if ($client instanceof CurlHandle) curl_close($client);
    if ($guest instanceof CurlHandle) curl_close($guest);
    if (is_resource($server)) {
        proc_terminate($server);
        proc_close($server);
    }
    if (is_file($temporaryFile)) @unlink($temporaryFile);
    foreach (h19Files($storage) as $name) {
        if (!in_array($name, $storageBefore, true)) @unlink($storage . DIRECTORY_SEPARATOR . $name);
    }
    foreach (h19Files($storage, '.trash') as $name) {
        if (!in_array($name, $trashBefore, true)) @unlink($storage . DIRECTORY_SEPARATOR . '.trash' . DIRECTORY_SEPARATOR . $name);
    }
    $database->exec("DELETE FROM security_score_contributors WHERE id>{$starts['security_score_contributors']}");
    $database->exec("DELETE FROM security_events WHERE id>{$starts['security_events']}");
    $database->exec("DELETE FROM security_sessions WHERE id>{$starts['security_sessions']}");
    $database->exec("DELETE FROM honeytoken_events WHERE id>{$starts['honeytoken_events']}");
    $database->exec("DELETE FROM documents WHERE id>{$starts['documents']}");
    $database->exec("DELETE FROM user_activity WHERE id>{$starts['user_activity']}");
    $database->exec("DELETE FROM users WHERE id>{$starts['users']}");
}

$residual = 0;
foreach ($trackedTables as $table) {
    $residual += (int) $database->query("SELECT COUNT(*) FROM {$table} WHERE id>{$starts[$table]}")->fetchColumn();
}
$storageClean = h19Files($storage) === $storageBefore && h19Files($storage, '.trash') === $trashBefore;
$check($residual === 0 && $storageClean, 'H19 HTTP database, active-file, and trash fixtures are fully cleaned');
echo 'Cleanup: ' . ($residual === 0 && $storageClean ? 'PASS' : 'FAIL') . PHP_EOL;
echo PHP_EOL . "{$passed} H19 HTTP/E2E storage checks passed, {$failed} failed, 0 skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
