<?php

declare(strict_types=1);

use App\Core\Env;

$root = dirname(__DIR__);
require $root . '/app/Core/Env.php';
Env::load($root . '/.env');

if ((string) getenv('TEST_DB_DATABASE') !== 'chimera_test') {
    echo "[FAIL] TEST_DB_DATABASE must be exactly chimera_test.\n";
    exit(1);
}
if ((string) getenv('DB_DATABASE') !== 'chimera' || (string) getenv('DB_PORT') !== '3308') {
    echo "[FAIL] Development database guard is not configured for chimera on port 3308.\n";
    exit(1);
}

$testUsername = (string) getenv('TEST_DB_USERNAME');
$testPassword = (string) getenv('TEST_DB_PASSWORD');
if ($testUsername === '' || $testPassword === '') {
    echo "[FAIL] Dedicated test credentials are required.\n";
    exit(1);
}

$pdo = new PDO(
    'mysql:host=127.0.0.1;port=3308;dbname=chimera_test;charset=utf8mb4',
    $testUsername,
    $testPassword,
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
);
$connection = $pdo->query('SELECT DATABASE() AS database_name, @@port AS server_port, CURRENT_USER() AS authenticated_user')->fetch();
if ($connection['database_name'] !== 'chimera_test' || (int) $connection['server_port'] !== 3308 || !str_starts_with($connection['authenticated_user'], 'chimera_test_app@')) {
    echo "[FAIL] HTTP E2E database connection is not safely isolated.\n";
    exit(1);
}
$eventStartId = (int) $pdo->query('SELECT COALESCE(MAX(id), 0) FROM security_events')->fetchColumn();
$securitySessionStartId = (int) $pdo->query('SELECT COALESCE(MAX(id), 0) FROM security_sessions')->fetchColumn();

$passes = 0;
$failures = 0;
$check = static function (bool $condition, string $label) use (&$passes, &$failures): void {
    if ($condition) {
        $passes++;
        echo "[PASS] {$label}\n";
    } else {
        $failures++;
        echo "[FAIL] {$label}\n";
    }
};

function e2eClient(): CurlHandle
{
    $client = curl_init();
    curl_setopt($client, CURLOPT_COOKIEFILE, '');
    curl_setopt($client, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($client, CURLOPT_HEADER, true);
    curl_setopt($client, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($client, CURLOPT_TIMEOUT, 10);
    return $client;
}

function e2eRequest(CurlHandle $client, string $baseUrl, string $method, string $path, array|string|null $fields = null): array
{
    curl_setopt($client, CURLOPT_URL, $baseUrl . $path);
    curl_setopt($client, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($client, CURLOPT_POST, $method === 'POST');
    if ($method === 'GET') {
        curl_setopt($client, CURLOPT_HTTPGET, true);
        curl_setopt($client, CURLOPT_POSTFIELDS, null);
    } elseif ($fields !== null) {
        $containsFile = is_array($fields) && array_filter($fields, static fn (mixed $value): bool => $value instanceof CURLFile) !== [];
        curl_setopt($client, CURLOPT_POSTFIELDS, $containsFile ? $fields : (is_array($fields) ? http_build_query($fields) : $fields));
    } else {
        curl_setopt($client, CURLOPT_POSTFIELDS, '');
    }
    $raw = curl_exec($client);
    if (!is_string($raw)) {
        throw new RuntimeException('HTTP request failed: ' . curl_error($client));
    }
    $headerSize = curl_getinfo($client, CURLINFO_HEADER_SIZE);
    $headerText = substr($raw, 0, $headerSize);
    $body = substr($raw, $headerSize);
    $headers = [];
    foreach (preg_split('/\r\n|\n|\r/', trim($headerText)) as $line) {
        if (str_contains($line, ':')) {
            [$name, $value] = explode(':', $line, 2);
            $headers[strtolower(trim($name))] = trim($value);
        }
    }
    return ['status' => (int) curl_getinfo($client, CURLINFO_RESPONSE_CODE), 'headers' => $headers, 'body' => $body];
}

function e2eCsrf(string $html): string
{
    if (!preg_match('/name="_token"\s+value="([^"]+)"/', $html, $matches)) {
        throw new RuntimeException('CSRF token was not present in the response.');
    }
    return html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function e2eSessionCookie(CurlHandle $client, string $sessionName): ?string
{
    $cookies = curl_getinfo($client, CURLINFO_COOKIELIST);
    foreach ($cookies as $cookie) {
        $parts = explode("\t", $cookie);
        if (count($parts) >= 7 && $parts[5] === $sessionName) {
            return $parts[6];
        }
    }
    return null;
}

function e2eUpload(CurlHandle $client, string $baseUrl, string $path, string $mime, string $postName): array
{
    $page = e2eRequest($client, $baseUrl, 'GET', '/documents');
    return e2eRequest($client, $baseUrl, 'POST', '/documents', [
        '_token' => e2eCsrf($page['body']),
        'document' => new CURLFile($path, $mime, $postName),
    ]);
}

$suffix = bin2hex(random_bytes(6));
$emails = [
    'a' => "owner-a-{$suffix}@e2e.chimera.test",
    'b' => "owner-b-{$suffix}@e2e.chimera.test",
    'admin' => "admin-{$suffix}@e2e.chimera.test",
    'security' => "security-{$suffix}@e2e.chimera.test",
];
$userPassword = 'SyntheticUser!2026';
$adminPassword = 'SyntheticAdmin!2026';
$securityPassword = 'SyntheticSecurity!2026';
$createdUserIds = [];
$createdDecoyIds = [];
$createdHoneytokenIds = [];
$clients = [];
$temporaryFiles = [];
$server = null;
$storageRoot = $root . '/storage/uploads/e2e-documents';
$logPath = $root . '/storage/logs/e2e-server.log';

if (!is_dir($storageRoot) && !mkdir($storageRoot, 0750, true) && !is_dir($storageRoot)) {
    echo "[FAIL] Could not create isolated E2E storage.\n";
    exit(1);
}
$storageRoot = realpath($storageRoot) ?: $storageRoot;

try {
    if ((int) $pdo->query('SELECT COUNT(*) FROM decoy_endpoints')->fetchColumn() !== 0 || (int) $pdo->query('SELECT COUNT(*) FROM honeytokens')->fetchColumn() !== 0) {
        throw new RuntimeException('E2E deception configuration requires an unseeded chimera_test database.');
    }
    $insertDecoy = $pdo->prepare('INSERT INTO decoy_endpoints (decoy_identifier, path, name, type, is_active, risk_weight, response_mode) VALUES (?, ?, ?, ?, 1, 0, ?)');
    foreach ([['DEC-E2E-ADMIN','/admin-old','Legacy Administration','WEB_ROUTE','BELIEVABLE_403'],['DEC-E2E-INTERNAL','/internal','Internal Portal','WEB_ROUTE','SYNTHETIC_LOGIN'],['DEC-E2E-DEBUG','/api/debug','Debug API','API_ROUTE','SYNTHETIC_JSON']] as $row) { $insertDecoy->execute($row); $createdDecoyIds[]=(int)$pdo->lastInsertId(); }
    $insertHoney = $pdo->prepare('INSERT INTO honeytokens (token_identifier, description, token_hash, is_active, risk_weight) VALUES (?, ?, ?, 1, 0)');
    foreach ([['HT-BACKUP-001','Synthetic backup reference.','CHM_HONEY_HT_BACKUP_001'],['HT-API-001','Synthetic API identifier.','CHM_HONEY_HT_API_001']] as $row) { $insertHoney->execute([$row[0],$row[1],hash('sha256',$row[2])]); $createdHoneytokenIds[]=(int)$pdo->lastInsertId(); }
    $insertRole = $pdo->prepare('INSERT INTO users (name, email, password_hash, role, is_active) VALUES (:name, :email, :password_hash, :role, 1)');
    $insertRole->execute(['name' => 'E2E Admin', 'email' => $emails['admin'], 'password_hash' => password_hash($adminPassword, PASSWORD_DEFAULT), 'role' => 'admin']);
    $createdUserIds[] = (int) $pdo->lastInsertId();
    $adminId = end($createdUserIds);
    $insertRole->execute(['name' => 'E2E Security Admin', 'email' => $emails['security'], 'password_hash' => password_hash($securityPassword, PASSWORD_DEFAULT), 'role' => 'security_admin']);
    $createdUserIds[] = (int) $pdo->lastInsertId();

    $portSocket = stream_socket_server('tcp://127.0.0.1:0', $socketErrorNumber, $socketErrorMessage);
    if (!is_resource($portSocket)) {
        throw new RuntimeException('Could not allocate an isolated HTTP test port.');
    }
    $socketName = stream_socket_get_name($portSocket, false);
    fclose($portSocket);
    $port = (int) substr(strrchr((string) $socketName, ':'), 1);
    $baseUrl = 'http://127.0.0.1:' . $port;
    $serverEnvironment = getenv();
    $serverEnvironment['CHIMERA_E2E_BASE_URL'] = $baseUrl;
    $serverEnvironment['CHIMERA_E2E_STORAGE'] = $storageRoot;

    $server = proc_open(
        [PHP_BINARY, '-d', 'upload_max_filesize=8M', '-d', 'post_max_size=9M', '-S', '127.0.0.1:' . $port, '-t', $root . '/public', $root . '/tests/e2e_server_router.php'],
        [0 => ['pipe', 'r'], 1 => ['file', $logPath, 'a'], 2 => ['file', $logPath, 'a']],
        $pipes,
        $root,
        $serverEnvironment
    );
    if (!is_resource($server)) {
        throw new RuntimeException('PHP test server could not be started.');
    }
    fclose($pipes[0]);
    $ready = false;
    for ($attempt = 0; $attempt < 30; $attempt++) {
        $probe = e2eClient();
        try {
            $response = e2eRequest($probe, $baseUrl, 'GET', '/');
            $ready = $response['status'] === 200;
        } catch (Throwable) {
            $ready = false;
        }
        curl_close($probe);
        if ($ready) {
            break;
        }
        usleep(100000);
    }
    if (!$ready) {
        throw new RuntimeException('PHP test server did not become ready.');
    }

    $legacyDecoy = e2eRequest(e2eClient(), $baseUrl, 'GET', '/admin-old');
    $internalDecoy = e2eRequest(e2eClient(), $baseUrl, 'GET', '/internal');
    e2eRequest(e2eClient(), $baseUrl, 'GET', '/admin');
    e2eRequest(e2eClient(), $baseUrl, 'GET', '/security');
    $debugDecoy = e2eRequest(e2eClient(), $baseUrl, 'GET', '/api/debug');
    $debugData = json_decode($debugDecoy['body'], true);
    $check($legacyDecoy['status'] === 403 && str_contains($legacyDecoy['body'], 'Legacy control plane') && !str_contains($legacyDecoy['body'], 'Maintenance context') && !str_contains($legacyDecoy['body'], 'CHM_HONEY_'), 'LOW profile returns the minimal controlled legacy decoy');
    $check($internalDecoy['status'] === 200 && str_contains($internalDecoy['body'], 'Internal services gateway') && str_contains($internalDecoy['body'], 'Service notices') && !str_contains($internalDecoy['body'], 'CHM_HONEY_'), 'MEDIUM profile adds safe synthetic context without a honeytoken');
    $debugMarkers = $debugData['diagnostic_markers'] ?? [];
    $check($debugDecoy['status'] === 200 && in_array('CHM_HONEY_HT_API_001', $debugMarkers, true) && !in_array('CHM_HONEY_HT_BACKUP_001', $debugMarkers, true), 'HIGH profile exposes one registered synthetic honeytoken');
    $scoreBeforeRefresh = (int)$pdo->query("SELECT threat_score FROM security_sessions WHERE id > {$securitySessionStartId} AND user_id IS NULL ORDER BY id DESC LIMIT 1")->fetchColumn();
    e2eRequest(e2eClient(), $baseUrl, 'GET', '/api/debug');
    $scoreAfterRefresh = (int)$pdo->query("SELECT threat_score FROM security_sessions WHERE id > {$securitySessionStartId} AND user_id IS NULL ORDER BY id DESC LIMIT 1")->fetchColumn();
    $latestDebugDelta = (int)$pdo->query("SELECT risk_delta FROM security_events WHERE id > {$eventStartId} AND event_type='DECOY_ACCESSED' AND endpoint='/api/debug' ORDER BY id DESC LIMIT 1")->fetchColumn();
    $check($scoreBeforeRefresh === $scoreAfterRefresh && $latestDebugDelta === 0, 'Repeated render of the same decoy does not inflate the assessment');
    $pdo->exec("UPDATE decoy_endpoints SET is_active = 0 WHERE path = '/internal'");
    $check(e2eRequest(e2eClient(), $baseUrl, 'GET', '/internal')['status'] === 404 && e2eRequest(e2eClient(), $baseUrl, 'GET', '/backup')['status'] === 404, 'Inactive and unknown decoys fail safely without synthetic content');
    $pdo->exec("UPDATE decoy_endpoints SET is_active = 1 WHERE path = '/internal'");
    $check(e2eRequest(e2eClient(), $baseUrl, 'GET', '/api/debug/verify?token=random')['status'] === 404, 'Malformed or random material cannot trigger a honeytoken');
    $check(e2eRequest(e2eClient(), $baseUrl, 'GET', '/api/debug/verify?token=CHM_HONEY_HT_API_001')['status'] === 410, 'Registered synthetic honeytoken produces a deterministic safe response');

    $clients['a'] = e2eClient();
    $clients['b'] = e2eClient();
    $clients['admin'] = e2eClient();
    $clients['security'] = e2eClient();
    $clients['guest'] = e2eClient();

    foreach (['a' => 'Owner A', 'b' => 'Owner B'] as $key => $name) {
        $register = e2eRequest($clients[$key], $baseUrl, 'GET', '/register');
        $result = e2eRequest($clients[$key], $baseUrl, 'POST', '/register', [
            '_token' => e2eCsrf($register['body']), 'name' => $name, 'email' => $emails[$key],
            'password' => $userPassword, 'password_confirmation' => $userPassword,
        ]);
        $check($result['status'] === 302 && ($result['headers']['location'] ?? '') === $baseUrl . '/dashboard', "HTTP registration succeeds for User " . strtoupper($key));
        $userId = (int) $pdo->query("SELECT id FROM users WHERE email = " . $pdo->quote($emails[$key]))->fetchColumn();
        $createdUserIds[] = $userId;
        ${"owner" . strtoupper($key) . "Id"} = $userId;
    }
    $honeyLogin = e2eRequest($clients['guest'], $baseUrl, 'GET', '/login');
    $honeyLogin = e2eRequest($clients['guest'], $baseUrl, 'POST', '/login', ['_token'=>e2eCsrf($honeyLogin['body']),'email'=>$emails['a'],'password'=>'CHM_HONEY_HT_API_001']);
    $check($honeyLogin['status'] === 302 && e2eRequest($clients['guest'], $baseUrl, 'GET', '/dashboard')['status'] === 302, 'Synthetic honeytoken cannot authenticate or access real resources');

    $dashboard = e2eRequest($clients['a'], $baseUrl, 'GET', '/dashboard');
    $logout = e2eRequest($clients['a'], $baseUrl, 'POST', '/logout', ['_token' => e2eCsrf($dashboard['body'])]);
    $check($logout['status'] === 302 && e2eRequest($clients['a'], $baseUrl, 'GET', '/dashboard')['status'] === 302, 'Logout destroys access to authenticated routes');

    $loginPage = e2eRequest($clients['a'], $baseUrl, 'GET', '/login');
    $sessionName = trim((string) getenv('SESSION_NAME')) ?: 'chimera_session';
    $guestSession = e2eSessionCookie($clients['a'], $sessionName);
    $invalidLogin = e2eRequest($clients['a'], $baseUrl, 'POST', '/login', ['_token' => e2eCsrf($loginPage['body']), 'email' => $emails['a'], 'password' => 'IncorrectSyntheticPassword']);
    $check($invalidLogin['status'] === 302 && ($invalidLogin['headers']['location'] ?? '') === $baseUrl . '/login', 'Invalid credentials are rejected safely');
    $loginPage = e2eRequest($clients['a'], $baseUrl, 'GET', '/login');
    $validLogin = e2eRequest($clients['a'], $baseUrl, 'POST', '/login', ['_token' => e2eCsrf($loginPage['body']), 'email' => $emails['a'], 'password' => $userPassword]);
    $authenticatedSession = e2eSessionCookie($clients['a'], $sessionName);
    $check($validLogin['status'] === 302 && $guestSession !== null && $authenticatedSession !== null && !hash_equals($guestSession, $authenticatedSession), 'Valid login establishes an authenticated regenerated session');

    $check(e2eRequest($clients['guest'], $baseUrl, 'GET', '/dashboard')['status'] === 302, 'Unauthenticated dashboard access redirects to login');
    $check(e2eRequest($clients['guest'], $baseUrl, 'GET', '/api/me')['status'] === 401, 'Unauthenticated API access returns 401');
    $check(e2eRequest($clients['a'], $baseUrl, 'GET', '/dashboard')['status'] === 200 && e2eRequest($clients['a'], $baseUrl, 'GET', '/profile')['status'] === 200 && e2eRequest($clients['a'], $baseUrl, 'GET', '/documents')['status'] === 200, 'User can access dashboard, profile, and own documents');
    $check(e2eRequest($clients['a'], $baseUrl, 'GET', '/admin')['status'] === 403 && e2eRequest($clients['a'], $baseUrl, 'GET', '/security')['status'] === 403, 'User is denied Admin and Security Admin dashboards');
    $check(e2eRequest($clients['a'], $baseUrl, 'POST', '/profile', ['name' => 'No Token'])['status'] === 419, 'Authenticated profile update rejects missing CSRF token');

    $profilePage = e2eRequest($clients['a'], $baseUrl, 'GET', '/profile');
    $profileUpdate = e2eRequest($clients['a'], $baseUrl, 'POST', '/profile', ['_token' => e2eCsrf($profilePage['body']), 'name' => 'Owner A Verified', 'role' => 'admin', 'id' => $adminId]);
    $ownerARow = $pdo->query("SELECT name, role FROM users WHERE id = {$ownerAId}")->fetch();
    $check($profileUpdate['status'] === 302 && $ownerARow['name'] === 'Owner A Verified' && $ownerARow['role'] === 'user', 'Profile update changes only the authenticated user allowlisted name');

    $loginRole = static function (CurlHandle $client, string $baseUrl, string $email, string $password): array {
        $page = e2eRequest($client, $baseUrl, 'GET', '/login');
        return e2eRequest($client, $baseUrl, 'POST', '/login', ['_token' => e2eCsrf($page['body']), 'email' => $email, 'password' => $password]);
    };
    $loginRole($clients['admin'], $baseUrl, $emails['admin'], $adminPassword);
    $loginRole($clients['security'], $baseUrl, $emails['security'], $securityPassword);
    $check(e2eRequest($clients['admin'], $baseUrl, 'GET', '/admin')['status'] === 200 && e2eRequest($clients['admin'], $baseUrl, 'GET', '/security')['status'] === 403, 'Admin can access Admin dashboard and is denied Security dashboard');
    $check(e2eRequest($clients['security'], $baseUrl, 'GET', '/security')['status'] === 200 && e2eRequest($clients['security'], $baseUrl, 'GET', '/admin')['status'] === 403, 'Security Admin can access Security dashboard and is denied Admin dashboard');
    curl_setopt($clients['guest'], CURLOPT_HTTPHEADER, ['Authorization: Bearer synthetic-secret-that-must-not-be-stored']);
    $guestSecurityApi = e2eRequest($clients['guest'], $baseUrl, 'GET', '/api/security/summary');
    curl_setopt($clients['guest'], CURLOPT_HTTPHEADER, []);
    $check($guestSecurityApi['status'] === 401 && e2eRequest($clients['a'], $baseUrl, 'GET', '/api/security/summary')['status'] === 403 && e2eRequest($clients['admin'], $baseUrl, 'GET', '/api/security/summary')['status'] === 403, 'Telemetry API rejects guest, User, and Admin roles');

    $contentA = "Synthetic document owned by User A.\n";
    $contentB = "Synthetic document owned by User B.\n";
    $pathA = tempnam(sys_get_temp_dir(), 'chimera-a-');
    $pathB = tempnam(sys_get_temp_dir(), 'chimera-b-');
    $pathPhp = tempnam(sys_get_temp_dir(), 'chimera-php-');
    $pathHtml = tempnam(sys_get_temp_dir(), 'chimera-html-');
    $pathLarge = tempnam(sys_get_temp_dir(), 'chimera-large-');
    $temporaryFiles = [$pathA, $pathB, $pathPhp, $pathHtml, $pathLarge];
    file_put_contents($pathA, $contentA);
    file_put_contents($pathB, $contentB);
    file_put_contents($pathPhp, "harmless text only\n");
    file_put_contents($pathHtml, '<html><body>harmless mismatch</body></html>');
    file_put_contents($pathLarge, str_repeat('L', 2048));

    $uploadA = e2eUpload($clients['a'], $baseUrl, $pathA, 'text/plain', '../../report.txt');
    $uploadB = e2eUpload($clients['b'], $baseUrl, $pathB, 'text/plain', 'owner-b.txt');
    $check($uploadA['status'] === 302 && $uploadB['status'] === 302, 'Users can upload harmless allowlisted documents');
    $documentA = $pdo->query("SELECT * FROM documents WHERE user_id = {$ownerAId} ORDER BY id DESC LIMIT 1")->fetch();
    $documentB = $pdo->query("SELECT * FROM documents WHERE user_id = {$ownerBId} ORDER BY id DESC LIMIT 1")->fetch();
    $storedA = $storageRoot . DIRECTORY_SEPARATOR . $documentA['storage_name'];
    $storedB = $storageRoot . DIRECTORY_SEPARATOR . $documentB['storage_name'];
    $check($documentA['original_name'] === 'report.txt' && preg_match('/\A[a-f0-9]{48}\.txt\z/', $documentA['storage_name']) && is_file($storedA), 'Traversal-style original name is reduced to metadata and random private storage is used');
    $check((int) $documentA['size_bytes'] === strlen($contentA) && hash_equals($documentA['checksum_sha256'], hash_file('sha256', $storedA)), 'Uploaded metadata size and checksum match the private file');
    $check(!str_starts_with(strtolower($storedA), strtolower(realpath($root . '/public'))), 'Uploaded file is outside the public web root');

    $duplicateUpload = e2eUpload($clients['a'], $baseUrl, $pathA, 'text/plain', 'report.txt');
    $documentsA = $pdo->query("SELECT * FROM documents WHERE user_id = {$ownerAId} ORDER BY id")->fetchAll();
    $duplicateDocument = end($documentsA);
    $check($duplicateUpload['status'] === 302 && count($documentsA) === 2 && $documentsA[0]['storage_name'] !== $documentsA[1]['storage_name'], 'Duplicate original filenames receive distinct internal storage names');

    $countBeforeRejects = (int) $pdo->query("SELECT COUNT(*) FROM documents WHERE user_id = {$ownerAId}")->fetchColumn();
    $check(e2eUpload($clients['a'], $baseUrl, $pathPhp, 'text/plain', 'harmless.php')['status'] === 302, 'Unsupported extension request is handled without server error');
    $check(e2eUpload($clients['a'], $baseUrl, $pathHtml, 'text/html', 'mismatch.txt')['status'] === 302, 'MIME mismatch request is handled without server error');
    $check(e2eUpload($clients['a'], $baseUrl, $pathLarge, 'text/plain', 'oversized.txt')['status'] === 302, 'Oversized upload request is handled without server error');
    $documentsPage = e2eRequest($clients['a'], $baseUrl, 'GET', '/documents');
    $malformed = e2eRequest($clients['a'], $baseUrl, 'POST', '/documents', ['_token' => e2eCsrf($documentsPage['body'])]);
    $unauthorizedUpload = e2eRequest($clients['guest'], $baseUrl, 'POST', '/documents', ['_token' => 'invalid']);
    $countAfterRejects = (int) $pdo->query("SELECT COUNT(*) FROM documents WHERE user_id = {$ownerAId}")->fetchColumn();
    $check($malformed['status'] === 302 && $unauthorizedUpload['status'] === 302 && $countAfterRejects === $countBeforeRejects, 'Malformed, unauthorized, unsupported, mismatched, and oversized uploads create no records');

    $listA = e2eRequest($clients['a'], $baseUrl, 'GET', '/documents');
    $check(str_contains($listA['body'], 'report.txt') && !str_contains($listA['body'], 'owner-b.txt'), 'User A document list excludes User B document metadata');
    $check(e2eRequest($clients['a'], $baseUrl, 'GET', '/documents/' . $documentA['id'])['status'] === 200 && e2eRequest($clients['a'], $baseUrl, 'GET', '/documents/' . $documentB['id'])['status'] === 404, 'Document detail permits owner and returns 404 to non-owner');
    $check(e2eRequest($clients['b'], $baseUrl, 'GET', '/documents/' . $documentB['id'])['status'] === 200 && e2eRequest($clients['b'], $baseUrl, 'GET', '/documents/' . $documentA['id'])['status'] === 404, 'Reverse document detail ownership matrix is enforced');

    $downloadA = e2eRequest($clients['a'], $baseUrl, 'GET', '/documents/' . $documentA['id'] . '/download');
    $foreignDownload = e2eRequest($clients['a'], $baseUrl, 'GET', '/documents/' . $documentB['id'] . '/download');
    $check($downloadA['status'] === 200 && hash_equals(hash('sha256', $contentA), hash('sha256', $downloadA['body'])), 'Owner download succeeds with matching SHA-256 content');
    $check(str_contains($downloadA['headers']['content-disposition'] ?? '', 'attachment;') && !str_contains(implode("\n", $downloadA['headers']), $storageRoot), 'Download uses safe attachment disposition without internal path disclosure');
    $check($foreignDownload['status'] === 404, 'User A cannot download User B document');
    $check(e2eRequest($clients['a'], $baseUrl, 'GET', '/documents/999999999/download')['status'] === 404, 'Invalid document download fails safely');

    $apiGuest = e2eRequest($clients['guest'], $baseUrl, 'GET', '/api/me');
    $apiMe = e2eRequest($clients['a'], $baseUrl, 'GET', '/api/me');
    $apiList = e2eRequest($clients['a'], $baseUrl, 'GET', '/api/documents');
    $apiOwn = e2eRequest($clients['a'], $baseUrl, 'GET', '/api/documents/' . $documentA['id']);
    $apiForeign = e2eRequest($clients['a'], $baseUrl, 'GET', '/api/documents/' . $documentB['id']);
    $apiInvalid = e2eRequest($clients['a'], $baseUrl, 'GET', '/api/documents/not-a-number');
    $apiCombined = $apiMe['body'] . $apiList['body'] . $apiOwn['body'];
    $check($apiGuest['status'] === 401 && $apiMe['status'] === 200, 'API authentication returns 401 to guest and success to owner');
    $check($apiOwn['status'] === 200 && $apiForeign['status'] === 404 && $apiInvalid['status'] === 404, 'API document endpoint enforces ownership and safe invalid-ID handling');
    $check(str_contains($apiList['body'], 'report.txt') && !str_contains($apiList['body'], 'owner-b.txt'), 'API document listing contains only owner records');
    $check(!preg_match('/password_hash|storage_name|csrf|session|DB_PASSWORD|stack trace|\\\\|[A-Za-z]:\//i', $apiCombined), 'API responses omit secrets, storage paths, sessions, and stack traces');

    file_put_contents($storageRoot . DIRECTORY_SEPARATOR . $duplicateDocument['storage_name'], 'tampered');
    $check(e2eRequest($clients['a'], $baseUrl, 'GET', '/documents/' . $duplicateDocument['id'] . '/download')['status'] === 404, 'Checksum mismatch fails safely');
    @unlink($storageRoot . DIRECTORY_SEPARATOR . $duplicateDocument['storage_name']);

    $deletePage = e2eRequest($clients['a'], $baseUrl, 'GET', '/documents/' . $documentA['id']);
    $deleteToken = e2eCsrf($deletePage['body']);
    $unauthorizedDelete = e2eRequest($clients['a'], $baseUrl, 'POST', '/documents/' . $documentB['id'] . '/delete', ['_token' => $deleteToken]);
    $check($unauthorizedDelete['status'] === 404 && is_file($storedB) && (int) $pdo->query("SELECT COUNT(*) FROM documents WHERE id = {$documentB['id']}")->fetchColumn() === 1, 'Unauthorized deletion returns 404 and preserves User B record and file');
    $check(e2eRequest($clients['a'], $baseUrl, 'POST', '/documents/' . $documentA['id'] . '/delete', [])['status'] === 419 && is_file($storedA), 'Document deletion requires CSRF and preserves file on rejection');
    $deletePage = e2eRequest($clients['a'], $baseUrl, 'GET', '/documents/' . $documentA['id']);
    $deleteA = e2eRequest($clients['a'], $baseUrl, 'POST', '/documents/' . $documentA['id'] . '/delete', ['_token' => e2eCsrf($deletePage['body'])]);
    clearstatcache(true, $storedA);
    $documentARemains = (int) $pdo->query("SELECT COUNT(*) FROM documents WHERE id = {$documentA['id']}")->fetchColumn();
    $check($deleteA['status'] === 302 && !is_file($storedA) && $documentARemains === 0, 'Authorized deletion removes database record and private file');

    $missingDeletePage = e2eRequest($clients['a'], $baseUrl, 'GET', '/documents/' . $duplicateDocument['id']);
    $missingDelete = e2eRequest($clients['a'], $baseUrl, 'POST', '/documents/' . $duplicateDocument['id'] . '/delete', ['_token' => e2eCsrf($missingDeletePage['body'])]);
    $check($missingDelete['status'] === 302 && (int) $pdo->query("SELECT COUNT(*) FROM documents WHERE id = {$duplicateDocument['id']}")->fetchColumn() === 0, 'Deletion safely removes a stale record when its file is missing');

    $activityTypes = $pdo->query("SELECT DISTINCT activity_type FROM user_activity WHERE user_id = {$ownerAId}")->fetchAll(PDO::FETCH_COLUMN);
    foreach (['ACCOUNT_CREATED', 'LOGIN', 'PROFILE_UPDATED', 'DOCUMENT_UPLOADED', 'DOCUMENT_DOWNLOADED', 'DOCUMENT_DELETED'] as $expectedActivity) {
        $check(in_array($expectedActivity, $activityTypes, true), "User activity records {$expectedActivity}");
    }
    $activityA = e2eRequest($clients['a'], $baseUrl, 'GET', '/activity');
    $check($activityA['status'] === 200 && !str_contains($activityA['body'], $emails['b']), 'User A activity page does not expose User B identity');
    $sensitiveActivity = (int) $pdo->query("SELECT COUNT(*) FROM user_activity WHERE user_id = {$ownerAId} AND (description LIKE '%password%' OR metadata_json LIKE '%session%' OR metadata_json LIKE '%DB_PASSWORD%')")->fetchColumn();
    $check($sensitiveActivity === 0, 'User activity contains no password, session, or database credential material');

    $adminPage = e2eRequest($clients['admin'], $baseUrl, 'GET', '/admin');
    $check($adminPage['status'] === 200 && str_contains($adminPage['body'], $emails['b']) && str_contains($adminPage['body'], 'owner-b.txt'), 'Admin dashboard renders real user, document, and activity data');
    $check(!str_contains($adminPage['body'], '$2y$') && !str_contains($adminPage['body'], $documentB['storage_name']), 'Admin dashboard omits password hashes and internal storage names');

    $bDeletePage = e2eRequest($clients['b'], $baseUrl, 'GET', '/documents/' . $documentB['id']);
    e2eRequest($clients['b'], $baseUrl, 'POST', '/documents/' . $documentB['id'] . '/delete', ['_token' => e2eCsrf($bDeletePage['body'])]);
    clearstatcache(true, $storedB);
    $check(!is_file($storedB) && (int) $pdo->query("SELECT COUNT(*) FROM documents WHERE id = {$documentB['id']}")->fetchColumn() === 0, 'User B can delete own document and storage is cleaned');
    $check(glob($storageRoot . DIRECTORY_SEPARATOR . '*') === [], 'Document workflow leaves no uploaded files in isolated E2E storage');

    $telemetryTypes = $pdo->query("SELECT DISTINCT event_type FROM security_events WHERE id > {$eventStartId}")->fetchAll(PDO::FETCH_COLUMN);
    foreach (['REGISTRATION_SUCCESS','LOGIN_SUCCESS','LOGIN_FAILURE','LOGOUT','ACCESS_DENIED','ROLE_ACCESS_DENIED','OWNERSHIP_ACCESS_DENIED','CSRF_REJECTED','DOCUMENT_UPLOAD_SUCCESS','DOCUMENT_UPLOAD_REJECTED','DOCUMENT_DOWNLOAD','DOCUMENT_DELETE','DOCUMENT_INTEGRITY_FAILURE','PROFILE_UPDATED'] as $expectedType) {
        $check(in_array($expectedType, $telemetryTypes, true), "Telemetry records {$expectedType}");
    }
    $securityDashboard = e2eRequest($clients['security'], $baseUrl, 'GET', '/security');
    $securitySummary = e2eRequest($clients['security'], $baseUrl, 'GET', '/api/security/summary');
    $securityEvents = e2eRequest($clients['security'], $baseUrl, 'GET', '/api/security/events?severity=MEDIUM');
    $latestEventId = (int) $pdo->query("SELECT MAX(id) FROM security_events WHERE id > {$eventStartId}")->fetchColumn();
    $securityEvent = e2eRequest($clients['security'], $baseUrl, 'GET', '/api/security/events/' . $latestEventId);
    $check($securityDashboard['status'] === 200 && str_contains($securityDashboard['body'], 'Telemetry overview'), 'Security Admin telemetry dashboard renders database-backed events');
    $check($securitySummary['status'] === 200 && $securityEvents['status'] === 200 && $securityEvent['status'] === 200, 'Security Admin telemetry APIs return summary, filtered list, and detail');
    $telemetryPayload = (string) $pdo->query("SELECT GROUP_CONCAT(CONCAT_WS('|', event_type, endpoint, user_agent_summary, metadata_json, description) SEPARATOR '\n') FROM security_events WHERE id > {$eventStartId}")->fetchColumn();
    $check(!str_contains($telemetryPayload, $userPassword) && !str_contains($telemetryPayload, $adminPassword) && !str_contains($telemetryPayload, $securityPassword) && !str_contains($telemetryPayload, 'synthetic-secret-that-must-not-be-stored'), 'Telemetry excludes passwords and Authorization headers');
    $check(!str_contains($telemetryPayload, $contentA) && !str_contains($telemetryPayload, $storageRoot) && !str_contains($telemetryPayload, $documentA['storage_name']), 'Telemetry excludes document contents and internal filesystem data');
    $telemetryMetadataPayload = (string) $pdo->query("SELECT GROUP_CONCAT(metadata_json SEPARATOR '\n') FROM security_events WHERE id > {$eventStartId}")->fetchColumn();
    $check(!preg_match('/\"(?:csrf|cookie|password_hash|db_password|session_identifier|authorization|credential)[^\"]*\"\s*:/i', $telemetryMetadataPayload), 'Telemetry metadata excludes CSRF, cookie, hash, credential, and session-secret fields');
    $sourceContext = $pdo->query("SELECT source_safe_identifier, metadata_json, risk_delta FROM security_events WHERE id > {$eventStartId} ORDER BY id DESC LIMIT 1")->fetch();
    $sourceMetadata = json_decode((string) $sourceContext['metadata_json'], true);
    $check(strlen((string) $sourceContext['source_safe_identifier']) === 64 && !array_key_exists('source_ip', $sourceMetadata) && (int) $sourceContext['risk_delta'] >= 0 && (int) $sourceContext['risk_delta'] <= 35, 'Telemetry stores only a safe source identifier and an explicit bounded event contribution');
    $deceptionDashboard = e2eRequest($clients['security'], $baseUrl, 'GET', '/security/deception');
    $deceptionSummary = e2eRequest($clients['security'], $baseUrl, 'GET', '/api/security/deception/summary');
    $decoyApi = e2eRequest($clients['security'], $baseUrl, 'GET', '/api/security/decoys');
    $honeyApi = e2eRequest($clients['security'], $baseUrl, 'GET', '/api/security/honeytokens');
    $deceptionEventsApi = e2eRequest($clients['security'], $baseUrl, 'GET', '/api/security/deception/events');
    $check($deceptionDashboard['status'] === 200 && str_contains($deceptionDashboard['body'], 'Cyber deception'), 'Security Admin can inspect the deception dashboard');
    $check($deceptionSummary['status'] === 200 && $decoyApi['status'] === 200 && $honeyApi['status'] === 200 && $deceptionEventsApi['status'] === 200, 'Security Admin deception APIs return summary, inventories, and events');
    $telemetryPresentation = $securityDashboard['body'] . $securityEvents['body'] . $securityEvent['body'] . $deceptionDashboard['body'] . $deceptionEventsApi['body'];
    $check(!preg_match('/source_ip|Source IP|source_safe_identifier|Source identifier/i', $telemetryPresentation), 'Telemetry and deception presentation expose neither raw nor pseudonymous source identifiers');
    $check(e2eRequest($clients['guest'], $baseUrl, 'GET', '/api/security/decoys')['status'] === 401 && e2eRequest($clients['a'], $baseUrl, 'GET', '/api/security/decoys')['status'] === 403 && e2eRequest($clients['admin'], $baseUrl, 'GET', '/api/security/decoys')['status'] === 403, 'Guest, User, and Admin cannot access deception APIs');
    $check(!preg_match('/token_hash|risk_weight|CHM_HONEY_/i', $honeyApi['body'] . $decoyApi['body']), 'Deception inventory APIs omit token material, hashes, and dormant risk weights');
    $deceptionTypes = $pdo->query("SELECT DISTINCT event_type FROM security_events WHERE id > {$eventStartId} AND event_type IN ('DECOY_ACCESSED','HONEYTOKEN_TRIGGERED')")->fetchAll(PDO::FETCH_COLUMN);
    $check(in_array('DECOY_ACCESSED',$deceptionTypes,true) && in_array('HONEYTOKEN_TRIGGERED',$deceptionTypes,true), 'Decoy and honeytoken interactions enter centralized telemetry');
    $check((int)$pdo->query('SELECT COUNT(*) FROM honeytoken_events')->fetchColumn() === 1, 'Honeytoken interaction creates one linked honeytoken event');
    $check(!str_contains($legacyDecoy['body'].$internalDecoy['body'].$debugDecoy['body'], $emails['a']) && !str_contains($legacyDecoy['body'].$internalDecoy['body'].$debugDecoy['body'], 'DB_PASSWORD'), 'Decoy responses contain no real user or environment data');
    $assessment = $pdo->query("SELECT id,threat_score,classification,request_count FROM security_sessions WHERE id > {$securitySessionStartId} AND user_id IS NULL ORDER BY threat_score DESC,id LIMIT 1")->fetch();
    $assessmentId = (int)$assessment['id'];
    $contributorSum = (int)$pdo->query("SELECT COALESCE(SUM(risk_delta),0) FROM security_score_contributors WHERE security_session_id={$assessmentId}")->fetchColumn();
    $check((int)$assessment['threat_score']===100 && $assessment['classification']==='CRITICAL' && min(100,$contributorSum)===100, 'E2E observed behavior produces bounded, reconstructible CRITICAL assessment');
    $linkedEvents = (int)$pdo->query("SELECT COUNT(*) FROM security_events WHERE id>{$eventStartId} AND security_session_id IS NOT NULL")->fetchColumn();
    $allEvents = (int)$pdo->query("SELECT COUNT(*) FROM security_events WHERE id>{$eventStartId}")->fetchColumn();
    $check($linkedEvents===$allEvents && $allEvents>0, 'All E2E telemetry with a safe source is correlated to security sessions');
    $threatDashboard=e2eRequest($clients['security'],$baseUrl,'GET','/security/threats');$threatList=e2eRequest($clients['security'],$baseUrl,'GET','/api/security/sessions');$threatDetail=e2eRequest($clients['security'],$baseUrl,'GET','/api/security/sessions/'.$assessmentId);$threatSummary=e2eRequest($clients['security'],$baseUrl,'GET','/api/security/threat-summary');
    $check($threatDashboard['status']===200 && str_contains($threatDashboard['body'],'Threat assessment'),'Security Admin can inspect the threat-assessment dashboard');
    $check($threatList['status']===200&&$threatDetail['status']===200&&$threatSummary['status']===200,'Security Admin assessment APIs return list, detail, and summary');
    $check(e2eRequest($clients['guest'],$baseUrl,'GET','/api/security/sessions')['status']===401&&e2eRequest($clients['a'],$baseUrl,'GET','/api/security/sessions')['status']===403&&e2eRequest($clients['admin'],$baseUrl,'GET','/api/security/sessions')['status']===403,'Guest, User, and Admin cannot access assessment APIs');
    $assessmentPayload=$threatList['body'].$threatDetail['body'].$threatSummary['body'];
    $check(!preg_match('/password|cookie|authorization|token_hash|CHM_HONEY_|storage_name|session_identifier|DB_PASSWORD/i',$assessmentPayload),'Assessment APIs omit secrets, token material, paths, and internal session identifiers');
    $adaptiveDashboard=e2eRequest($clients['security'],$baseUrl,'GET','/security/adaptive');$adaptiveSummary=e2eRequest($clients['security'],$baseUrl,'GET','/api/security/adaptive/summary');$adaptiveEvents=e2eRequest($clients['security'],$baseUrl,'GET','/api/security/adaptive/events');$adaptiveSession=e2eRequest($clients['security'],$baseUrl,'GET','/api/security/sessions/'.$assessmentId.'/deception');
    $check($adaptiveDashboard['status']===200&&str_contains($adaptiveDashboard['body'],'Adaptive deception'),'Security Admin can inspect the adaptive deception dashboard');
    $check($adaptiveSummary['status']===200&&$adaptiveEvents['status']===200&&$adaptiveSession['status']===200,'Security Admin adaptive APIs return summary, events, and session explanation');
    $check(e2eRequest($clients['guest'],$baseUrl,'GET','/api/security/adaptive/summary')['status']===401&&e2eRequest($clients['a'],$baseUrl,'GET','/api/security/adaptive/summary')['status']===403&&e2eRequest($clients['admin'],$baseUrl,'GET','/api/security/adaptive/summary')['status']===403,'Guest, User, and Admin cannot access adaptive APIs');
    $adaptivePayload=$adaptiveSummary['body'].$adaptiveEvents['body'].$adaptiveSession['body'];
    $check(!preg_match('/password|cookie|authorization|token_hash|CHM_HONEY_|storage_name|session_identifier|source_ip|source_safe_identifier|DB_PASSWORD/i',$adaptivePayload),'Adaptive APIs omit secrets, source identifiers, honeytoken material, paths, and internal session identifiers');
    $adaptiveDeltas=(int)$pdo->query("SELECT COALESCE(SUM(risk_delta),0) FROM security_events WHERE id>{$eventStartId} AND event_type IN ('DECEPTION_PROFILE_SELECTED','DECEPTION_PROFILE_CHANGED','ADAPTIVE_DECOY_RENDERED')")->fetchColumn();
    $check($adaptiveDeltas===0,'Profile selection, transitions, and adaptive rendering contribute zero threat points');
    $debugAfterAssessment=e2eRequest($clients['guest'],$baseUrl,'GET','/api/debug');$criticalData=json_decode($debugAfterAssessment['body'],true);$criticalMarkers=$criticalData['diagnostic_markers']??[];
    $check($debugAfterAssessment['status']===200&&isset($criticalData['service_map'])&&in_array('CHM_HONEY_HT_API_001',$criticalMarkers,true)&&in_array('CHM_HONEY_HT_BACKUP_001',$criticalMarkers,true),'CRITICAL profile returns the richest safe synthetic response with registered markers');
    $check(!str_contains($debugAfterAssessment['body'],$emails['a'])&&!str_contains($debugAfterAssessment['body'],'DB_PASSWORD'),'Adaptive response remains isolated from real application and environment data');
} catch (Throwable $exception) {
    $failures++;
    echo '[FAIL] HTTP E2E exception: ' . $exception->getMessage() . "\n";
} finally {
    foreach ($clients as $client) {
        curl_close($client);
    }
    if (is_resource($server)) {
        proc_terminate($server);
        proc_close($server);
    }
    foreach ($temporaryFiles as $temporaryFile) {
        if (is_string($temporaryFile) && is_file($temporaryFile)) {
            @unlink($temporaryFile);
        }
    }
    if ($createdUserIds !== []) {
        $placeholders = implode(',', array_fill(0, count($createdUserIds), '?'));
        $documents = $pdo->prepare("SELECT storage_name FROM documents WHERE user_id IN ({$placeholders})");
        $documents->execute($createdUserIds);
        foreach ($documents->fetchAll(PDO::FETCH_COLUMN) as $storageName) {
            if (preg_match('/\A[a-f0-9]{48}\.(pdf|txt|csv|md)\z/', $storageName)) {
                @unlink($storageRoot . DIRECTORY_SEPARATOR . $storageName);
            }
        }
        $deleteUsers = $pdo->prepare("DELETE FROM users WHERE id IN ({$placeholders})");
        $deleteUsers->execute($createdUserIds);
    }
    $deleteTelemetry = $pdo->prepare('DELETE FROM security_events WHERE id > ?');
    $deleteTelemetry->execute([$eventStartId]);
    $deleteSessions = $pdo->prepare('DELETE FROM security_sessions WHERE id > ?');
    $deleteSessions->execute([$securitySessionStartId]);
    if ($createdDecoyIds !== []) { $placeholders=implode(',',array_fill(0,count($createdDecoyIds),'?')); $delete=$pdo->prepare("DELETE FROM decoy_endpoints WHERE id IN ({$placeholders})"); $delete->execute($createdDecoyIds); }
    if ($createdHoneytokenIds !== []) { $placeholders=implode(',',array_fill(0,count($createdHoneytokenIds),'?')); $delete=$pdo->prepare("DELETE FROM honeytokens WHERE id IN ({$placeholders})"); $delete->execute($createdHoneytokenIds); }
}

echo "\n{$passes} HTTP E2E checks passed, {$failures} failed.\n";
exit($failures === 0 ? 0 : 1);
