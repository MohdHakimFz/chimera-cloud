<?php

declare(strict_types=1);

$app = require dirname(__DIR__) . '/bootstrap/app.php';

use App\Core\Request;
use App\Core\Router;
use App\Security\ProfileValidator;
use App\Security\UploadValidator;
use App\Services\DocumentStorage;

$phaseTwoFailures = [];
$phaseTwoPasses = 0;

function phase2_check(bool $condition, string $label): void
{
    global $phaseTwoFailures, $phaseTwoPasses;
    if ($condition) {
        $phaseTwoPasses++;
        echo "[PASS] {$label}\n";
        return;
    }
    $phaseTwoFailures[] = $label;
    echo "[FAIL] {$label}\n";
}

function phase2_source(string $relative): string
{
    $contents = file_get_contents(BASE_PATH . '/' . $relative);
    return $contents === false ? '' : $contents;
}

$validProfile = ProfileValidator::validateName('  Nur   Aisyah  ');
phase2_check($validProfile['value'] === 'Nur Aisyah' && $validProfile['errors'] === [], 'Profile validation normalizes an allowed name');
phase2_check(ProfileValidator::validateName('A')['errors'] !== [], 'Profile validation rejects a short name');
phase2_check(ProfileValidator::validateName(str_repeat('a', 101))['errors'] !== [], 'Profile validation enforces maximum length');

$textPath = tempnam(sys_get_temp_dir(), 'chimera-upload-');
$largePath = tempnam(sys_get_temp_dir(), 'chimera-large-');
$htmlPath = tempnam(sys_get_temp_dir(), 'chimera-html-');
if ($textPath === false || $largePath === false || $htmlPath === false) {
    throw new RuntimeException('Temporary test files could not be created.');
}
file_put_contents($textPath, "Synthetic laboratory notes.\n");
file_put_contents($largePath, str_repeat('A', 128));
file_put_contents($htmlPath, '<html><script>alert(1)</script></html>');

$validUpload = UploadValidator::validate(['error' => UPLOAD_ERR_OK, 'tmp_name' => $textPath, 'size' => filesize($textPath), 'name' => 'notes.txt'], 1024, ['pdf', 'txt']);
phase2_check($validUpload['errors'] === [] && $validUpload['mime_type'] === 'text/plain', 'Upload validation accepts an allowlisted text document with detected MIME');

$largeUpload = UploadValidator::validate(['error' => UPLOAD_ERR_OK, 'tmp_name' => $largePath, 'size' => filesize($largePath), 'name' => 'large.txt'], 64, ['txt']);
phase2_check(isset($largeUpload['errors']['document']), 'Upload validation enforces the configured file-size limit');

$extensionUpload = UploadValidator::validate(['error' => UPLOAD_ERR_OK, 'tmp_name' => $textPath, 'size' => filesize($textPath), 'name' => 'payload.php'], 1024, ['pdf', 'txt']);
phase2_check(isset($extensionUpload['errors']['document']), 'Upload validation rejects a non-allowlisted executable extension');

$mimeUpload = UploadValidator::validate(['error' => UPLOAD_ERR_OK, 'tmp_name' => $htmlPath, 'size' => filesize($htmlPath), 'name' => 'page.txt'], 1024, ['txt']);
phase2_check(isset($mimeUpload['errors']['document']), 'Upload validation rejects extension and detected-MIME mismatch');

$safeName = UploadValidator::safeOriginalName('../../private/notes.txt');
phase2_check($safeName === 'notes.txt', 'Original filename metadata strips path traversal components');
$storageOne = UploadValidator::generateStorageName('txt');
$storageTwo = UploadValidator::generateStorageName('txt');
phase2_check($storageOne !== $storageTwo && (bool) preg_match('/\A[a-f0-9]{48}\.txt\z/', $storageOne), 'Storage filename generation is random, duplicate-safe, and constrained');

$pathRejected = false;
try {
    DocumentStorage::path('../outside.php');
} catch (RuntimeException) {
    $pathRejected = true;
}
phase2_check($pathRejected, 'Storage path resolution rejects traversal and arbitrary filenames');
phase2_check(!DocumentStorage::isInsidePublicRoot(BASE_PATH . '/storage/uploads/documents'), 'Default document storage is outside the public root');
phase2_check(DocumentStorage::isInsidePublicRoot(BASE_PATH . '/public/uploads'), 'Public-root storage is detected and rejected');
phase2_check(DocumentStorage::isAbsolutePath(BASE_PATH . '/storage/uploads/documents'), 'Default storage path is absolute');
phase2_check(!DocumentStorage::isAbsolutePath('storage/uploads/documents'), 'Relative custom storage paths are rejected');

$router = new Router();
$capturedId = null;
$router->get('/unit/documents/{id}', static function (Request $request) use (&$capturedId): void {
    $capturedId = $request->route('id');
});
$router->dispatch(new Request('GET', '/unit/documents/42', [], [], []));
phase2_check($capturedId === '42', 'Router resolves a constrained numeric route parameter');

$routes = phase2_source('routes/web.php');
$documentModel = phase2_source('app/Models/Document.php');
$documentController = phase2_source('app/Controllers/DocumentController.php');
$documentService = phase2_source('app/Services/DocumentService.php');
$apiController = phase2_source('app/Controllers/ApiController.php');
$activityModel = phase2_source('app/Models/Activity.php');
$profileController = phase2_source('app/Controllers/ProfileController.php');

phase2_check(str_contains($documentModel, 'WHERE id = :id AND user_id = :user_id'), 'Document lookup enforces ownership in the SQL query');
phase2_check(str_contains($documentController, 'Document::findOwned('), 'Document view, download, and delete use the owned lookup');
phase2_check(str_contains($routes, "'/documents/{id}/delete'") && str_contains($routes, 'VerifyCsrf::class'), 'Document deletion is POST-only and CSRF protected');
phase2_check(str_contains($routes, "'/profile'") && str_contains($profileController, 'ProfileValidator::validateName'), 'Profile route is authenticated, CSRF protected, and allowlist validated');
phase2_check(str_contains($routes, "'/api/documents/{id}'") && str_contains($apiController, 'Document::findOwned('), 'API document lookup enforces session ownership');
phase2_check(str_contains($routes, "'/api/me'") && substr_count($routes, '[Authenticate::class]') >= 4, 'API endpoints require session authentication');
phase2_check(!str_contains($apiController, 'storage_name') && !str_contains($apiController, 'checksum_sha256'), 'API responses omit internal storage and checksum fields');
phase2_check(str_contains($activityModel, 'WHERE user_id = :user_id'), 'User activity history is scoped to its account owner');
phase2_check(str_contains($routes, "new RequireRole(['admin'])") && str_contains($routes, "new RequireRole(['security_admin'])"), 'Admin and Security Admin remain separate exact roles');
phase2_check(!str_contains($profileController, "input('role") && !str_contains($profileController, "input('id"), 'Profile update does not mass-assign role or account ID');
phase2_check(str_contains($documentService, "hash_file('sha256'") && str_contains($documentService, 'hash_equals('), 'Downloads verify stored file integrity before streaming');

@unlink($textPath);
@unlink($largePath);
@unlink($htmlPath);

echo "\n{$phaseTwoPasses} Phase 2 checks passed, " . count($phaseTwoFailures) . " failed.\n";
exit($phaseTwoFailures === [] ? 0 : 1);
