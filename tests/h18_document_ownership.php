<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Security\SecurityEventTaxonomy;
use App\Services\ThreatScoringService;

$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$source = static fn (string $path): string => (string) file_get_contents($root . '/' . $path);

$routes = $source('routes/web.php');
$controller = $source('app/Controllers/DocumentController.php');
$api = $source('app/Controllers/ApiController.php');
$model = $source('app/Models/Document.php');
$service = $source('app/Services/DocumentService.php');
$storage = $source('app/Services/DocumentStorage.php');
$upload = $source('app/Security/UploadValidator.php');
$schema = $source('database/schema.sql');
$rootPolicy = $source('.htaccess');
$storagePolicy = $source('storage/.htaccess');
$uploadPolicy = $source('storage/uploads/.htaccess');
$indexView = $source('resources/views/documents/index.php');
$showView = $source('resources/views/documents/show.php');

$documentRoutes = [
    "->get('/documents', [DocumentController::class, 'index'], [Authenticate::class])",
    "->post('/documents', [DocumentController::class, 'upload'], [Authenticate::class, VerifyCsrf::class])",
    "->get('/documents/{id}', [DocumentController::class, 'show'], [Authenticate::class])",
    "->get('/documents/{id}/download', [DocumentController::class, 'download'], [Authenticate::class])",
    "->post('/documents/{id}/delete', [DocumentController::class, 'delete'], [Authenticate::class, VerifyCsrf::class])",
    "->get('/api/documents', [ApiController::class, 'documents'], [Authenticate::class])",
    "->get('/api/documents/{id}', [ApiController::class, 'document'], [Authenticate::class])",
];
foreach ($documentRoutes as $declaration) {
    $check(str_contains($routes, $declaration), 'Document route preserves its exact authentication/CSRF contract: ' . $declaration);
}

$check(substr_count($routes, "'/documents") === 5, 'Exactly five HTML document routes exist');
$check(substr_count($routes, "'/api/documents") === 2, 'Exactly two document API routes exist');
$check(!preg_match('/->(?:put|patch|delete)\(\'\/(?:api\/)?documents/i', $routes), 'No alternate PUT, PATCH, or DELETE document mutation route exists');
$check(str_contains($model, 'WHERE id = :id AND user_id = :user_id LIMIT 1'), 'Owned lookup constrains document ID and authenticated user ID in SQL');
$check(str_contains($model, 'WHERE user_id = :user_id ORDER BY created_at DESC, id DESC'), 'Document listing is owner scoped and deterministically ordered');
$check(str_contains($controller, '$document = $this->ownedDocument($request);'), 'HTML detail, download, and delete share the owner-enforcement boundary');
$check(substr_count($controller, '$document = $this->ownedDocument($request);') === 3, 'All three HTML object operations invoke ownership enforcement');
$check(str_contains($api, 'Document::findOwned((int) $request->route(\'id\', 0), (int) $account[\'id\'])'), 'API detail uses the same owner-constrained lookup');
$check(str_contains($service, 'DELETE FROM documents WHERE id = :id AND user_id = :user_id'), 'Deletion repeats the owner predicate at the mutation boundary');
$check(str_contains($service, 'rowCount() !== 1') && str_contains($service, 'rollBack()') && str_contains($service, 'rename($quarantine, $path)'), 'Deletion rolls back and restores quarantine when the owner predicate fails');
$check(strpos($controller, '$document = $this->ownedDocument($request);') < strpos($controller, 'DocumentService::downloadable($document)'), 'Download ownership is enforced before storage access');
$check(strpos($controller, '$document = $this->ownedDocument($request);', strpos($controller, 'public function delete')) < strpos($controller, 'DocumentService::deleteOwned('), 'Delete ownership is enforced before storage mutation');
$check(str_contains($controller, "Response::abort(404, 'The requested document could not be found.')"), 'HTML ownership denial uses a generic not-found response');
$check(str_contains($api, "'code' => 'NOT_FOUND', 'message' => 'Resource not found.'"), 'API ownership denial uses a generic not-found response');
$check(substr_count($controller, "'OWNERSHIP_ACCESS_DENIED'") === 1 && substr_count($api, "'OWNERSHIP_ACCESS_DENIED'") === 1, 'HTML and API ownership boundaries emit the intended event type');

$definition = SecurityEventTaxonomy::definition('OWNERSHIP_ACCESS_DENIED');
$check($definition['category'] === 'AUTHORIZATION' && $definition['severity'] === 'MEDIUM' && $definition['outcome'] === 'DENIED', 'Ownership-denial taxonomy is AUTHORIZATION/MEDIUM/DENIED');
$check(ThreatScoringService::weight('OWNERSHIP_ACCESS_DENIED') === 12, 'Ownership-denial score remains exactly +12');

$check((bool) preg_match('/user_id\s+BIGINT\s+UNSIGNED\s+NOT NULL/i', $schema) && str_contains($schema, 'FOREIGN KEY (user_id) REFERENCES users(id)'), 'Schema preserves the non-null document owner relationship');
$check(str_contains($storage, "[a-f0-9]{48}\\.(pdf|txt|csv|md)") && str_contains($upload, 'random_bytes(24)'), 'Private storage names remain random 48-hex allowlisted names');
$check(str_contains($storage, 'is_link($path)') || str_contains($service, 'is_link($path)'), 'Download rejects symbolic-link document targets');
$check(str_contains($service, "hash_file('sha256'") && str_contains($service, 'hash_equals('), 'Authorized download verifies size and SHA-256 integrity');
$check(str_contains($rootPolicy, 'CHIMERA_INFINITYFREE_PROTECTED_ROOT') && str_contains($rootPolicy, 'storage'), 'InfinityFree root policy retains the protected-storage denial boundary');
$check(str_contains($storagePolicy, 'Require all denied') && str_contains($uploadPolicy, 'Require all denied'), 'Storage and upload directories retain direct-web denial rules');
$check(str_contains($indexView, 'csrf_field()') && str_contains($showView, 'csrf_field()'), 'Upload and delete forms render the shared CSRF field');
$check(!str_contains($api, 'storage_name') && !str_contains($api, 'checksum_sha256') && !str_contains($api, 'user_id'), 'Document API presentation omits storage, checksum, and owner identifiers');
$check(!preg_match('/ownership|document/i', $source('app/Controllers/LabController.php')), 'Synthetic LAB controller remains independent from legitimate document ownership');
$check((string) env('VULNERABILITY_LAB_ENABLED', 'false') !== 'true', 'Vulnerability LAB remains disabled by default');

echo PHP_EOL . "{$passed} H18 static ownership checks passed, {$failed} failed, 0 skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
