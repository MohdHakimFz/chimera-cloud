<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Lab\ControlledLabService;
use App\Lab\LabResponse;
use App\Models\VulnerabilityModule;
use App\Services\SecurityEventService;

final class LabController
{
    public function index(Request $request): never
    {
        SecurityEventService::record($request, 'LAB_MODULE_ACCESSED', null, ['target_type' => 'lab_registry', 'metadata' => ['module_identifier' => 'LAB-INDEX', 'lab_authorized' => true]]);
        LabResponse::html('lab/index', ['modules' => VulnerabilityModule::all()]);
    }

    public function robots(Request $request): never
    {
        SecurityEventService::record($request, 'LAB_MODULE_ACCESSED', null, ['target_type' => 'lab_recon', 'metadata' => ['module_identifier' => 'LAB-RECON', 'lab_authorized' => true]]);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-CHIMERA-Lab: controlled-enabled');
        echo "User-agent: *\nDisallow: /lab/sqli\nDisallow: /lab/idor\nDisallow: /lab/xss\n";
        exit;
    }

    public function sqli(Request $request): never
    {
        $module = $this->module('CHIM-VULN-002');
        $input = (string) $request->query('q', '');
        $rows = $input === '' ? [] : ControlledLabService::sqlSearch($input, $module['state']);
        $this->observe($request, $module, $input !== '', 'bounded_sql_filter', ['result_count' => count($rows)]);
        LabResponse::html('lab/sqli', ['module' => $module, 'input' => $input, 'rows' => $rows]);
    }

    public function idor(Request $request): never
    {
        $module = $this->module('CHIM-VULN-001');
        $actor = (string) $request->query('actor', 'analyst-a');
        $objectId = (string) $request->query('id', '');
        $object = $objectId === '' ? null : ControlledLabService::idorLookup($actor, $objectId, $module['state']);
        $this->observe($request, $module, $objectId !== '', 'synthetic_object_lookup', ['object_returned' => $object !== null]);
        LabResponse::html('lab/idor', ['module' => $module, 'actor' => $actor, 'objectId' => $objectId, 'object' => $object]);
    }

    public function xss(Request $request): never
    {
        $module = $this->module('CHIM-VULN-003');
        $provided = $request->query('input', null) !== null;
        $reflection = ControlledLabService::reflectedInput((string) $request->query('input', 'lab-marker'));
        $this->observe($request, $module, $provided, 'sandboxed_reflection', ['input_length' => mb_strlen($reflection)]);
        LabResponse::html('lab/xss', ['module' => $module, 'reflection' => $reflection]);
    }

    private function module(string $identifier): array
    {
        $module = VulnerabilityModule::findActive($identifier);
        if ($module === null) {
            Response::abort(404, 'The requested page could not be found.');
        }
        return $module;
    }

    private function observe(Request $request, array $module, bool $interaction, string $technique, array $facts): void
    {
        $metadata = array_merge(['module_identifier' => $module['vulnerability_identifier'], 'module_state' => $module['state'], 'lab_authorized' => true, 'technique' => $technique], $facts);
        SecurityEventService::record($request, 'LAB_MODULE_ACCESSED', null, ['target_type' => 'lab_module', 'target_identifier' => $module['vulnerability_identifier'], 'metadata' => $metadata]);
        if ($interaction) {
            $event = $module['state'] === 'VULNERABLE' ? 'LAB_VULNERABILITY_INTERACTION' : 'LAB_REMEDIATED_TEST';
            SecurityEventService::record($request, $event, null, ['target_type' => 'lab_module', 'target_identifier' => $module['vulnerability_identifier'], 'metadata' => $metadata]);
        }
    }
}
