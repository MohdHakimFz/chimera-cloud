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

$storage = $root . '/storage/uploads/h19-integration-documents';
if (!is_dir($storage) && !mkdir($storage, 0750, true) && !is_dir($storage)) {
    echo "[FAIL] H19 integration storage could not be created." . PHP_EOL;
    exit(1);
}
$storage = realpath($storage) ?: $storage;
putenv('DB_DATABASE=chimera_test');
$_ENV['DB_DATABASE'] = 'chimera_test';
putenv('DB_USERNAME=' . $testUsername);
$_ENV['DB_USERNAME'] = $testUsername;
putenv('DB_PASSWORD=' . $testPassword);
$_ENV['DB_PASSWORD'] = $testPassword;
putenv('DEPLOYMENT_STORAGE_MODE=PRIVATE_OUTSIDE_WEBROOT');
$_ENV['DEPLOYMENT_STORAGE_MODE'] = 'PRIVATE_OUTSIDE_WEBROOT';
putenv('DOCUMENT_STORAGE_PATH=' . $storage);
$_ENV['DOCUMENT_STORAGE_PATH'] = $storage;
require $root . '/bootstrap/app.php';

use App\Core\Database;
use App\Security\UploadValidator;
use App\Services\DocumentService;
use App\Services\DocumentStorage;

$database = Database::connection();
$connection = $database->query('SELECT DATABASE() database_name,@@port server_port,CURRENT_USER() authenticated_user')->fetch();
if (!is_array($connection) || $connection['database_name'] !== 'chimera_test' || (int) $connection['server_port'] !== 3308 || !str_starts_with((string) $connection['authenticated_user'], 'chimera_test_app@')) {
    echo "[FAIL] Unsafe H19 integration target." . PHP_EOL;
    exit(1);
}

$trackedTables = ['users','documents','user_activity','security_events','security_sessions','security_score_contributors','vulnerability_state_changes'];
$starts = [];
foreach ($trackedTables as $table) {
    $starts[$table] = (int) $database->query("SELECT COALESCE(MAX(id),0) FROM {$table}")->fetchColumn();
}
$labBefore = $database->query('SELECT id,state,is_active,updated_at FROM vulnerability_modules ORDER BY id')->fetchAll();
$schemaTablesBefore = (int) $database->query('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()')->fetchColumn();
$passed = 0;
$failed = 0;
$skipped = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$setStorage = static function (string $path): void {
    putenv('DOCUMENT_STORAGE_PATH=' . $path);
    $_ENV['DOCUMENT_STORAGE_PATH'] = $path;
};
$createdFiles = [];

try {
    $suffix = bin2hex(random_bytes(6));
    $insertUser = $database->prepare('INSERT INTO users(name,email,password_hash,role,is_active) VALUES(?,?,?,?,1)');
    $insertUser->execute(['H19 Storage User', "h19-storage-{$suffix}@test.chimera", password_hash(bin2hex(random_bytes(18)), PASSWORD_DEFAULT), 'user']);
    $userId = (int) $database->lastInsertId();
    $check((int) $database->query("SELECT COUNT(*) FROM users WHERE id>{$starts['users']}")->fetchColumn() === 1, 'Exactly one isolated standard USER fixture exists');

    DocumentStorage::ensureDirectories();
    $resolvedRoot = DocumentStorage::root();
    $publicRoot = realpath($root . '/public') ?: $root . '/public';
    $check($resolvedRoot === $storage && !DocumentStorage::isInsidePublicRoot($resolvedRoot), 'Configured document root resolves to the isolated private location outside public');

    $contents = "H19 harmless private-storage sentinel {$suffix}.\n";
    $storageName = UploadValidator::generateStorageName('txt');
    $secondName = UploadValidator::generateStorageName('txt');
    $check((bool) preg_match('/\A[a-f0-9]{48}\.txt\z/', $storageName), 'Generated internal filename is 48 lowercase hexadecimal characters plus an allowed extension');
    $check($storageName !== $secondName, 'Duplicate logical original names resolve to independent random internal names');
    $check($storageName !== 'h19-document.txt' && !str_contains($storageName, 'h19-document'), 'Original user filename does not control the physical storage filename');

    $invalidNames = ['../' . $storageName, '..\\' . $storageName, 'nested/' . $storageName, 'nested\\' . $storageName, str_repeat('a', 48) . '.php', str_repeat('a', 47) . '.txt', str_repeat('g', 48) . '.txt', strtoupper(str_repeat('a', 48)) . '.TXT'];
    $invalidRejected = true;
    foreach ($invalidNames as $invalidName) {
        try {
            DocumentStorage::path($invalidName);
            $invalidRejected = false;
        } catch (RuntimeException) {
        }
    }
    $check($invalidRejected, 'Traversal, separators, arbitrary extensions, and malformed internal names are rejected');

    $setStorage('storage/uploads/documents');
    $relativeRejected = false;
    try {
        DocumentStorage::root();
    } catch (RuntimeException) {
        $relativeRejected = true;
    }
    $setStorage($publicRoot . DIRECTORY_SEPARATOR . 'h19-invalid');
    $publicRejected = false;
    try {
        DocumentStorage::root();
    } catch (RuntimeException) {
        $publicRejected = true;
    }
    $setStorage($storage);
    $check($relativeRejected && $publicRejected, 'Relative and public-root storage configurations fail closed');

    $path = DocumentStorage::path($storageName);
    file_put_contents($path, $contents);
    @chmod($path, 0640);
    $createdFiles[] = $path;
    $checksum = hash_file('sha256', $path);
    $insertDocument = $database->prepare('INSERT INTO documents(user_id,original_name,storage_name,mime_type,size_bytes,checksum_sha256) VALUES(?,?,?,?,?,?)');
    $insertDocument->execute([$userId, 'h19-document.txt', $storageName, 'text/plain', strlen($contents), $checksum]);
    $documentId = (int) $database->lastInsertId();
    $document = $database->query("SELECT * FROM documents WHERE id={$documentId}")->fetch();
    $check(str_starts_with(realpath($path) ?: $path, $resolvedRoot . DIRECTORY_SEPARATOR) && file_get_contents($path) === $contents, 'Active file remains confined beneath the private root with byte-identical content');
    $check(is_array($document) && hash_equals((string) $document['checksum_sha256'], (string) hash_file('sha256', $path)) && DocumentService::downloadable($document) === $path, 'SHA-256 and application download integrity verification remain correct');

    $linkName = UploadValidator::generateStorageName('txt');
    $linkPath = DocumentStorage::path($linkName);
    if (@symlink($path, $linkPath)) {
        $createdFiles[] = $linkPath;
        $linkDocument = $document;
        $linkDocument['storage_name'] = $linkName;
        $linkRejected = false;
        try {
            DocumentService::downloadable($linkDocument);
        } catch (RuntimeException) {
            $linkRejected = true;
        }
        $check($linkRejected, 'Individual symlink storage targets are rejected before download');
    } else {
        $skipped++;
        echo '[SKIP] Symlink creation is unavailable under the current Windows privilege/filesystem policy.' . PHP_EOL;
    }

    $trashPath = DocumentStorage::trashPath($storageName);
    $trashDirectory = $storage . DIRECTORY_SEPARATOR . '.trash';
    $trashPattern = '/\A' . preg_quote($storageName, '/') . '\.[a-f0-9]{16}\z/';
    $check(dirname($trashPath) === $trashDirectory && preg_match($trashPattern, basename($trashPath)) === 1, 'Trash path stays beneath documents/.trash and derives only from the validated name plus a random suffix');

    $rowBeforeRollback = $document;
    $digestBeforeRollback = hash_file('sha256', $path);
    $rollbackRaised = false;
    try {
        DocumentService::deleteOwned($document, $userId + 999999);
    } catch (RuntimeException) {
        $rollbackRaised = true;
    }
    clearstatcache(true, $path);
    $rowAfterRollback = $database->query("SELECT * FROM documents WHERE id={$documentId}")->fetch();
    $trashAfterRollback = array_values(array_filter(glob($trashDirectory . DIRECTORY_SEPARATOR . '*') ?: [], 'is_file'));
    $check($rollbackRaised && $rowAfterRollback === $rowBeforeRollback && is_file($path) && hash_file('sha256', $path) === $digestBeforeRollback && $trashAfterRollback === [], 'Failed ownership predicate rolls back and restores the active file without a trash residue');

    DocumentService::deleteOwned($document, $userId);
    clearstatcache(true, $path);
    $createdFiles = array_values(array_filter($createdFiles, static fn (string $file): bool => $file !== $path));
    $deletedRow = (int) $database->query("SELECT COUNT(*) FROM documents WHERE id={$documentId}")->fetchColumn();
    $trashAfterDelete = array_values(array_filter(glob($trashDirectory . DIRECTORY_SEPARATOR . '*') ?: [], 'is_file'));
    $deleteActivity = (int) $database->query("SELECT COUNT(*) FROM user_activity WHERE user_id={$userId} AND activity_type='DOCUMENT_DELETED'")->fetchColumn();
    $check($deletedRow === 0 && !is_file($path) && $trashAfterDelete === [] && $deleteActivity === 1, 'Normal owner deletion removes row and active file and leaves no H19 trash fixture');

    $check((int) $database->query("SELECT COUNT(*) FROM security_score_contributors WHERE id>{$starts['security_score_contributors']}")->fetchColumn() === 0, 'Normal owner storage workflow creates no positive score contributor');
    $check($database->query('SELECT id,state,is_active,updated_at FROM vulnerability_modules ORDER BY id')->fetchAll() === $labBefore && (int) $database->query("SELECT COUNT(*) FROM vulnerability_state_changes WHERE id>{$starts['vulnerability_state_changes']}")->fetchColumn() === 0, 'Vulnerability-module and LAB state remain unchanged');
} catch (Throwable $exception) {
    $failed++;
    echo '[FAIL] H19 integration exception: ' . $exception->getMessage() . PHP_EOL;
} finally {
    $database->exec("DELETE FROM security_score_contributors WHERE id>{$starts['security_score_contributors']}");
    $database->exec("DELETE FROM security_events WHERE id>{$starts['security_events']}");
    $database->exec("DELETE FROM security_sessions WHERE id>{$starts['security_sessions']}");
    $database->exec("DELETE FROM documents WHERE id>{$starts['documents']}");
    $database->exec("DELETE FROM user_activity WHERE id>{$starts['user_activity']}");
    $database->exec("DELETE FROM vulnerability_state_changes WHERE id>{$starts['vulnerability_state_changes']}");
    $database->exec("DELETE FROM users WHERE id>{$starts['users']}");
    foreach ($createdFiles as $file) {
        if (is_link($file) || is_file($file)) {
            @unlink($file);
        }
    }
    foreach (glob($storage . DIRECTORY_SEPARATOR . '.trash' . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
        if (is_file($file) || is_link($file)) {
            @unlink($file);
        }
    }
}

$residual = 0;
foreach ($trackedTables as $table) {
    $residual += (int) $database->query("SELECT COUNT(*) FROM {$table} WHERE id>{$starts[$table]}")->fetchColumn();
}
$remainingFiles = array_values(array_filter(glob($storage . DIRECTORY_SEPARATOR . '*') ?: [], static fn (string $file): bool => is_file($file) || is_link($file)));
$remainingTrash = array_values(array_filter(glob($storage . DIRECTORY_SEPARATOR . '.trash' . DIRECTORY_SEPARATOR . '*') ?: [], static fn (string $file): bool => is_file($file) || is_link($file)));
$schemaTablesAfter = (int) $database->query('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()')->fetchColumn();
$check($residual === 0 && $remainingFiles === [] && $remainingTrash === [], 'H19 integration database, active-file, symlink, and trash fixtures are fully cleaned');
$check($schemaTablesAfter === $schemaTablesBefore && $schemaTablesAfter === 11, 'chimera_test remains structurally intact with the expected 11-table schema');

echo 'Cleanup: ' . ($residual === 0 && $remainingFiles === [] && $remainingTrash === [] ? 'PASS' : 'FAIL') . PHP_EOL;
echo PHP_EOL . "{$passed} H19 integration storage checks passed, {$failed} failed, {$skipped} skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
