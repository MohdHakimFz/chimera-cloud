<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Core\Session;
use App\Lab\ControlledLabService;
use App\Models\VulnerabilityModule;
use App\Security\Auth;
use App\Services\SecurityEventService;
use RuntimeException;

final class LabManagementController
{
    public function index(Request $request): never
    {
        Response::view('security/lab', [
            'title' => 'Controlled Vulnerability Lab',
            'enabled' => ControlledLabService::enabled(),
            'modules' => VulnerabilityModule::all(),
            'history' => VulnerabilityModule::stateHistory(),
            'events' => VulnerabilityModule::recentLabEvents(),
            'statusMessage' => Session::pullFlash('lab_status'),
        ]);
    }

    public function changeState(Request $request): never
    {
        $target = strtoupper(trim((string) $request->input('state', '')));
        $account = Auth::user();
        if ($account === null) {
            Response::abort(403, 'You do not have permission to change lab state.');
        }
        try {
            $change = VulnerabilityModule::changeState((int) $request->route('id', 0), $target, (int) $account['id'], 'Security Admin selected an explicit controlled-lab state.');
        } catch (RuntimeException) {
            Response::abort(404, 'The requested lab module or state was not found.');
        }
        SecurityEventService::record($request, 'LAB_MODULE_STATE_CHANGED', (int) $account['id'], [
            'target_type' => 'lab_module', 'target_identifier' => $change['identifier'],
            'metadata' => ['module_identifier' => $change['identifier'], 'from_state' => $change['from_state'], 'to_state' => $change['to_state'], 'changed' => $change['changed'], 'lab_authorized' => true],
        ]);
        Session::flash('lab_status', $change['changed'] ? 'Lab module state updated.' : 'Lab module was already in the selected state.');
        Response::redirect('/security/lab');
    }
}
