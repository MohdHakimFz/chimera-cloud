<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Core\Session;
use App\Models\User;
use App\Security\Auth;
use App\Security\ProfileValidator;
use App\Services\SecurityEventService;

final class ProfileController
{
    public function show(Request $request): never
    {
        Response::view('profile/show', ['title' => 'Profile', 'account' => Auth::user()]);
    }

    public function update(Request $request): never
    {
        $account = Auth::user();
        $validated = ProfileValidator::validateName((string) $request->input('name', ''));
        Session::put('_old', ['name' => $validated['value']]);
        if ($validated['errors'] !== []) {
            SecurityEventService::record($request, 'INVALID_REQUEST', (int) $account['id'], ['target_type' => 'profile', 'metadata' => ['validation_fields' => array_keys($validated['errors'])]]);
            Session::put('_errors', $validated['errors']);
            Response::redirect('/profile');
        }

        User::updateName((int) $account['id'], $validated['value']);
        SecurityEventService::record($request, 'PROFILE_UPDATED', (int) $account['id'], ['target_type' => 'account', 'target_identifier' => (string) $account['id']]);
        Session::forget('_old');
        Session::flash('success', 'Your profile was updated.');
        Response::redirect('/profile');
    }
}
