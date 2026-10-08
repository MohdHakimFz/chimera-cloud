<?php

declare(strict_types=1);

namespace App\Security;

use InvalidArgumentException;

final class SecurityEventTaxonomy
{
    private const EVENTS = [
        'LOGIN_SUCCESS' => ['AUTHENTICATION', 'INFO', 'SUCCESS', 'Login completed successfully.'],
        'LOGIN_FAILURE' => ['AUTHENTICATION', 'MEDIUM', 'FAILURE', 'Login attempt failed.'],
        'LOGOUT' => ['AUTHENTICATION', 'INFO', 'SUCCESS', 'Authenticated session logged out.'],
        'REGISTRATION_SUCCESS' => ['AUTHENTICATION', 'INFO', 'SUCCESS', 'Account registration completed.'],
        'ACCESS_DENIED' => ['AUTHORIZATION', 'LOW', 'DENIED', 'Protected resource access was denied.'],
        'ROLE_ACCESS_DENIED' => ['AUTHORIZATION', 'MEDIUM', 'DENIED', 'Role-restricted access was denied.'],
        'OWNERSHIP_ACCESS_DENIED' => ['AUTHORIZATION', 'MEDIUM', 'DENIED', 'Owner-scoped resource access was denied.'],
        'CSRF_REJECTED' => ['REQUEST_SECURITY', 'MEDIUM', 'REJECTED', 'Request failed CSRF validation.'],
        'INVALID_REQUEST' => ['REQUEST_SECURITY', 'LOW', 'REJECTED', 'Request validation failed.'],
        'DOCUMENT_UPLOAD_SUCCESS' => ['DOCUMENT_SECURITY', 'INFO', 'SUCCESS', 'Document upload completed.'],
        'DOCUMENT_UPLOAD_REJECTED' => ['DOCUMENT_SECURITY', 'LOW', 'REJECTED', 'Document upload was rejected.'],
        'DOCUMENT_DOWNLOAD' => ['DOCUMENT_SECURITY', 'INFO', 'SUCCESS', 'Authorized document download completed.'],
        'DOCUMENT_DELETE' => ['DOCUMENT_SECURITY', 'INFO', 'SUCCESS', 'Authorized document deletion completed.'],
        'DOCUMENT_INTEGRITY_FAILURE' => ['DOCUMENT_SECURITY', 'HIGH', 'FAILURE', 'Stored document integrity validation failed.'],
        'PROFILE_UPDATED' => ['ACCOUNT', 'INFO', 'SUCCESS', 'Account profile was updated.'],
        'SECURITY_RELEVANT_APPLICATION_ERROR' => ['APPLICATION', 'HIGH', 'ERROR', 'A security-relevant application operation failed.'],
        'DECOY_ACCESSED' => ['DECEPTION', 'MEDIUM', 'SUCCESS', 'A configured decoy endpoint was accessed.'],
        'HONEYTOKEN_TRIGGERED' => ['DECEPTION', 'HIGH', 'SUCCESS', 'A registered synthetic honeytoken was presented.'],
        'DECEPTION_PROFILE_SELECTED' => ['DECEPTION', 'INFO', 'SUCCESS', 'A safe deception profile was selected.'],
        'DECEPTION_PROFILE_CHANGED' => ['DECEPTION', 'INFO', 'SUCCESS', 'A safe deception profile transition occurred.'],
        'ADAPTIVE_DECOY_RENDERED' => ['DECEPTION', 'INFO', 'SUCCESS', 'A configured decoy rendered a safe adaptive profile.'],
        'LAB_MODULE_ACCESSED' => ['LAB', 'INFO', 'SUCCESS', 'An authorized controlled-lab module was accessed.'],
        'LAB_VULNERABILITY_INTERACTION' => ['LAB', 'INFO', 'SUCCESS', 'A controlled vulnerable-mode interaction was observed.'],
        'LAB_REMEDIATED_TEST' => ['LAB', 'INFO', 'SUCCESS', 'A controlled remediated-mode test was observed.'],
        'LAB_MODULE_STATE_CHANGED' => ['LAB', 'INFO', 'SUCCESS', 'A controlled-lab module state was changed.'],
    ];

    public static function definition(string $eventType): array
    {
        if (!isset(self::EVENTS[$eventType])) {
            throw new InvalidArgumentException('Unknown security event type.');
        }
        [$category, $severity, $outcome, $description] = self::EVENTS[$eventType];
        return compact('category', 'severity', 'outcome', 'description');
    }

    public static function eventTypes(): array
    {
        return array_keys(self::EVENTS);
    }

    public static function severities(): array
    {
        return ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    }

    public static function categories(): array
    {
        return ['AUTHENTICATION', 'AUTHORIZATION', 'REQUEST_SECURITY', 'DOCUMENT_SECURITY', 'ACCOUNT', 'APPLICATION', 'DECEPTION', 'LAB'];
    }
}
