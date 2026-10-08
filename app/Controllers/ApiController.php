<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Models\Document;
use App\Security\Auth;
use App\Services\SecurityEventService;

final class ApiController
{
    public function me(Request $request): never
    {
        $account = Auth::user();
        Response::json(['data' => [
            'id' => (int) $account['id'],
            'name' => $account['name'],
            'email' => $account['email'],
            'role' => $account['role'],
            'created_at' => $account['created_at'],
        ]]);
    }

    public function documents(Request $request): never
    {
        $account = Auth::user();
        $documents = array_map([$this, 'presentDocument'], Document::allForUser((int) $account['id']));
        Response::json(['data' => $documents, 'meta' => ['count' => count($documents)]]);
    }

    public function document(Request $request): never
    {
        $account = Auth::user();
        $document = Document::findOwned((int) $request->route('id', 0), (int) $account['id']);
        if ($document === null) {
            SecurityEventService::record($request, 'OWNERSHIP_ACCESS_DENIED', (int) $account['id'], [
                'target_type' => 'document', 'target_identifier' => (string) $request->route('id', 0),
                'metadata' => ['surface' => 'api'],
            ]);
            Response::json(['error' => ['code' => 'NOT_FOUND', 'message' => 'Resource not found.']], 404);
        }
        Response::json(['data' => $this->presentDocument($document)]);
    }

    private function presentDocument(array $document): array
    {
        return [
            'id' => (int) $document['id'],
            'name' => $document['original_name'],
            'mime_type' => $document['mime_type'],
            'size_bytes' => (int) $document['size_bytes'],
            'created_at' => $document['created_at'],
            'updated_at' => $document['updated_at'] ?? $document['created_at'],
        ];
    }
}
