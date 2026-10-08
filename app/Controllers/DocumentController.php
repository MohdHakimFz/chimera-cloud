<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Core\Session;
use App\Models\Activity;
use App\Models\Document;
use App\Security\Auth;
use App\Services\DocumentService;
use App\Services\SecurityEventService;
use RuntimeException;

final class DocumentController
{
    public function index(Request $request): never
    {
        $account = Auth::user();
        Response::view('documents/index', [
            'title' => 'Documents',
            'documents' => Document::allForUser((int) $account['id']),
            'summary' => Document::summaryForUser((int) $account['id']),
            'maxBytes' => (int) env('DOCUMENT_MAX_BYTES', 5242880),
            'allowedExtensions' => array_values(array_filter(array_map('trim', explode(',', (string) env('DOCUMENT_ALLOWED_EXTENSIONS', 'pdf,txt,csv,md'))))),
        ]);
    }

    public function upload(Request $request): never
    {
        $account = Auth::user();
        $result = DocumentService::upload((int) $account['id'], $request->file('document') ?? []);
        if ($result['errors'] !== []) {
            SecurityEventService::record($request, 'DOCUMENT_UPLOAD_REJECTED', (int) $account['id'], [
                'target_type' => 'document',
                'metadata' => ['validation_fields' => array_keys($result['errors'])],
            ]);
            Session::put('_errors', $result['errors']);
            Response::redirect('/documents');
        }

        SecurityEventService::record($request, 'DOCUMENT_UPLOAD_SUCCESS', (int) $account['id'], [
            'target_type' => 'document', 'target_identifier' => (string) $result['document_id'],
        ]);

        Session::flash('success', 'Document uploaded securely.');
        Response::redirect('/documents/' . $result['document_id']);
    }

    public function show(Request $request): never
    {
        $document = $this->ownedDocument($request);
        Response::view('documents/show', ['title' => 'Document details', 'document' => $document]);
    }

    public function download(Request $request): never
    {
        $account = Auth::user();
        $document = $this->ownedDocument($request);
        try {
            $path = DocumentService::downloadable($document);
        } catch (RuntimeException $exception) {
            SecurityEventService::record($request, 'DOCUMENT_INTEGRITY_FAILURE', (int) $account['id'], [
                'target_type' => 'document', 'target_identifier' => (string) $document['id'],
                'metadata' => ['reason' => 'integrity_or_availability_check_failed'],
            ]);
            error_log('CHIMERA document download unavailable for record ' . $document['id'] . ': ' . $exception->getMessage());
            Response::abort(404, 'The requested document is unavailable.');
        }

        Activity::record((int) $account['id'], 'DOCUMENT_DOWNLOADED', 'Document downloaded.', [
            'document_id' => (int) $document['id'],
            'original_name' => (string) $document['original_name'],
        ]);
        SecurityEventService::record($request, 'DOCUMENT_DOWNLOAD', (int) $account['id'], [
            'target_type' => 'document', 'target_identifier' => (string) $document['id'],
        ]);
        Response::download($path, (string) $document['original_name'], (string) $document['mime_type']);
    }

    public function delete(Request $request): never
    {
        $account = Auth::user();
        $document = $this->ownedDocument($request);
        DocumentService::deleteOwned($document, (int) $account['id']);
        SecurityEventService::record($request, 'DOCUMENT_DELETE', (int) $account['id'], [
            'target_type' => 'document', 'target_identifier' => (string) $document['id'],
        ]);
        Session::flash('success', 'Document deleted.');
        Response::redirect('/documents');
    }

    private function ownedDocument(Request $request): array
    {
        $account = Auth::user();
        $documentId = (int) $request->route('id', 0);
        $document = Document::findOwned($documentId, (int) $account['id']);
        if ($document === null) {
            SecurityEventService::record($request, 'OWNERSHIP_ACCESS_DENIED', (int) $account['id'], [
                'target_type' => 'document', 'target_identifier' => (string) $documentId,
            ]);
            Response::abort(404, 'The requested document could not be found.');
        }
        return $document;
    }
}
