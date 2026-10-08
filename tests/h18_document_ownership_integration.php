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

$storage = $root . '/storage/uploads/h18-integration-documents';
if (!is_dir($storage) && !mkdir($storage, 0750, true) && !is_dir($storage)) {
    echo "[FAIL] H18 integration storage could not be created." . PHP_EOL;
    exit(1);
}
$storage = realpath($storage) ?: $storage;
putenv('DB_DATABASE=chimera_test');
$_ENV['DB_DATABASE'] = 'chimera_test';
putenv('DB_USERNAME=' . $testUsername);
$_ENV['DB_USERNAME'] = $testUsername;
putenv('DB_PASSWORD=' . $testPassword);
$_ENV['DB_PASSWORD'] = $testPassword;
putenv('DOCUMENT_STORAGE_PATH=' . $storage);
$_ENV['DOCUMENT_STORAGE_PATH'] = $storage;
require $root . '/bootstrap/app.php';

use App\Core\Database;
use App\Core\Request;
use App\Models\Document;
use App\Services\DocumentService;
use App\Services\SecurityEventService;

$database = Database::connection();
$connection = $database->query('SELECT DATABASE() database_name,@@port server_port,CURRENT_USER() authenticated_user')->fetch();
if (!is_array($connection) || $connection['database_name'] !== 'chimera_test' || (int) $connection['server_port'] !== 3308 || !str_starts_with((string) $connection['authenticated_user'], 'chimera_test_app@')) {
    echo "[FAIL] Unsafe H18 integration target." . PHP_EOL;
    exit(1);
}

$trackedTables = ['users','documents','user_activity','security_events','security_sessions','security_score_contributors'];
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
$createdFiles = [];

try {
    $suffix = bin2hex(random_bytes(6));
    $insertUser = $database->prepare('INSERT INTO users(name,email,password_hash,role,is_active) VALUES(?,?,?,?,1)');
    $insertUser->execute(['H18 Integration A', "h18-a-{$suffix}@test.chimera", password_hash(bin2hex(random_bytes(18)), PASSWORD_DEFAULT), 'user']);
    $userA = (int) $database->lastInsertId();
    $insertUser->execute(['H18 Integration B', "h18-b-{$suffix}@test.chimera", password_hash(bin2hex(random_bytes(18)), PASSWORD_DEFAULT), 'user']);
    $userB = (int) $database->lastInsertId();

    $contents = "H18 harmless ownership integration fixture.\n";
    $storageName = bin2hex(random_bytes(24)) . '.txt';
    $path = $storage . DIRECTORY_SEPARATOR . $storageName;
    file_put_contents($path, $contents);
    $createdFiles[] = $path;
    $checksum = hash('sha256', $contents);
    $insertDocument = $database->prepare('INSERT INTO documents(user_id,original_name,storage_name,mime_type,size_bytes,checksum_sha256) VALUES(?,?,?,?,?,?)');
    $insertDocument->execute([$userA, 'h18-integration.txt', $storageName, 'text/plain', strlen($contents), $checksum]);
    $documentId = (int) $database->lastInsertId();

    $owned = Document::findOwned($documentId, $userA);
    $foreign = Document::findOwned($documentId, $userB);
    $check(is_array($owned) && (int) $owned['user_id'] === $userA && $foreign === null, 'Owner-constrained lookup returns Document A only to USER A');
    $check(count(Document::allForUser($userA)) >= 1 && array_filter(Document::allForUser($userB), static fn (array $row): bool => (int) $row['id'] === $documentId) === [], 'Owner-scoped listings isolate Document A from USER B');

    $beforeRow = $database->query("SELECT * FROM documents WHERE id={$documentId}")->fetch();
    $beforeDigest = hash_file('sha256', $path);
    $rollbackWorked = false;
    try {
        DocumentService::deleteOwned($owned, $userB);
    } catch (RuntimeException) {
        $rollbackWorked = true;
    }
    clearstatcache(true, $path);
    $afterRow = $database->query("SELECT * FROM documents WHERE id={$documentId}")->fetch();
    $trash = glob($storage . DIRECTORY_SEPARATOR . '.trash' . DIRECTORY_SEPARATOR . '*') ?: [];
    $check($rollbackWorked && $beforeRow === $afterRow && is_file($path) && hash_file('sha256', $path) === $beforeDigest && $trash === [], 'Defense-in-depth delete predicate rolls back and restores the file for a foreign user ID');

    $requests = [
        new Request('GET', "/documents/{$documentId}", [], [], ['REMOTE_ADDR'=>'198.51.100.180','HTTP_USER_AGENT'=>'CHIMERA H18 Local Integration']),
        new Request('GET', "/documents/{$documentId}/download", [], [], ['REMOTE_ADDR'=>'198.51.100.180','HTTP_USER_AGENT'=>'CHIMERA H18 Local Integration']),
        new Request('GET', "/api/documents/{$documentId}", [], [], ['REMOTE_ADDR'=>'198.51.100.180','HTTP_USER_AGENT'=>'CHIMERA H18 Local Integration']),
        new Request('POST', "/documents/{$documentId}/delete", [], [], ['REMOTE_ADDR'=>'198.51.100.180','HTTP_USER_AGENT'=>'CHIMERA H18 Local Integration']),
    ];
    $eventIds = [];
    foreach ($requests as $request) {
        $eventIds[] = SecurityEventService::record($request, 'OWNERSHIP_ACCESS_DENIED', $userB, [
            'target_type'=>'document', 'target_identifier'=>(string) $documentId,
        ]);
    }
    $ids = implode(',', array_map('intval', $eventIds));
    $events = $database->query("SELECT id,security_session_id,event_type,severity,risk_delta,endpoint,http_method,metadata_json FROM security_events WHERE id IN ({$ids}) ORDER BY id")->fetchAll();
    $sessionId = (int) $events[0]['security_session_id'];
    $contributors = $database->query("SELECT id,security_session_id,rule_code,label,risk_delta FROM security_score_contributors WHERE security_session_id={$sessionId} AND rule_code='OWNERSHIP_ACCESS_DENIED' ORDER BY id")->fetchAll();
    $session = $database->query("SELECT threat_score,classification,request_count FROM security_sessions WHERE id={$sessionId}")->fetch();
    $consistent = count($events) === 4 && count($contributors) === 4;
    foreach ($events as $event) {
        $metadata = json_decode((string) $event['metadata_json'], true) ?: [];
        $matching = array_filter($contributors, static fn (array $row): bool => str_starts_with((string) $row['label'], 'Event #' . $event['id'] . ':'));
        $consistent = $consistent
            && $event['event_type'] === 'OWNERSHIP_ACCESS_DENIED'
            && $event['severity'] === 'MEDIUM'
            && (int) $event['risk_delta'] === 12
            && ($metadata['category'] ?? null) === 'AUTHORIZATION'
            && ($metadata['outcome'] ?? null) === 'DENIED'
            && ($metadata['target_type'] ?? null) === 'document'
            && ($metadata['target_identifier'] ?? null) === (string) $documentId
            && count($matching) === 1
            && (int) reset($matching)['security_session_id'] === (int) $event['security_session_id']
            && (int) reset($matching)['risk_delta'] === 12;
    }
    $check($consistent, 'Four ownership denials create exact matching event/session/contributor evidence');
    $check((int) $session['threat_score'] === 48 && $session['classification'] === 'HIGH' && (int) $session['request_count'] === 4, 'Four local ownership denials accumulate deterministically to 48/HIGH');

    $persisted = json_encode([$events, $contributors], JSON_THROW_ON_ERROR);
    $check(!preg_match('/source_ip|source_safe_identifier|source_identifier|source_hash|storage_name|checksum_sha256|password|cookie|csrf|authorization_header/i', $persisted) && !str_contains($persisted, $contents), 'Ownership evidence excludes raw/internal sources, document secrets, credentials, and content');
    $check($database->query("SELECT * FROM documents WHERE id={$documentId}")->fetch() === $beforeRow && hash_file('sha256', $path) === $beforeDigest, 'Security evidence creation leaves Document A row and bytes unchanged');
} catch (Throwable $exception) {
    $failed++;
    echo '[FAIL] H18 integration exception: ' . $exception->getMessage() . PHP_EOL;
} finally {
    $database->exec("DELETE FROM security_score_contributors WHERE id>{$starts['security_score_contributors']}");
    $database->exec("DELETE FROM security_events WHERE id>{$starts['security_events']}");
    $database->exec("DELETE FROM security_sessions WHERE id>{$starts['security_sessions']}");
    $database->exec("DELETE FROM documents WHERE id>{$starts['documents']}");
    $database->exec("DELETE FROM user_activity WHERE id>{$starts['user_activity']}");
    $database->exec("DELETE FROM users WHERE id>{$starts['users']}");
    foreach ($createdFiles as $file) {
        if (is_file($file)) {
            @unlink($file);
        }
    }
    foreach (glob($storage . DIRECTORY_SEPARATOR . '.trash' . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
        if (is_file($file)) {
            @unlink($file);
        }
    }
}

$residual = 0;
foreach ($trackedTables as $table) {
    $residual += (int) $database->query("SELECT COUNT(*) FROM {$table} WHERE id>{$starts[$table]}")->fetchColumn();
}
$remainingFiles = array_values(array_filter(glob($storage . DIRECTORY_SEPARATOR . '*') ?: [], 'is_file'));
$remainingTrash = array_values(array_filter(glob($storage . DIRECTORY_SEPARATOR . '.trash' . DIRECTORY_SEPARATOR . '*') ?: [], 'is_file'));
$check($residual === 0 && $remainingFiles === [] && $remainingTrash === [], 'H18 integration database, active-file, and trash fixtures are fully cleaned');

echo 'Cleanup: ' . ($residual === 0 && $remainingFiles === [] && $remainingTrash === [] ? 'PASS' : 'FAIL') . PHP_EOL;
echo PHP_EOL . "{$passed} H18 integration ownership checks passed, {$failed} failed, 0 skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
