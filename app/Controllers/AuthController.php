<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Core\Session;
use App\Models\User;
use App\Security\Auth;
use App\Services\SecurityEventService;
use PDOException;

final class AuthController
{
    public function showLogin(Request $request): never
    {
        Response::view('auth/login', ['title' => 'Sign in']);
    }

    public function login(Request $request): never
    {
        $email = strtolower(trim((string) $request->input('email')));
        $password = (string) $request->input('password');
        Session::put('_old', ['email' => $email]);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
            SecurityEventService::record($request, 'LOGIN_FAILURE', null, ['metadata' => ['reason' => 'invalid_login_request']]);
            Session::put('_errors', ['email' => 'Enter a valid email address and password.']);
            Response::redirect('/login');
        }

        if (!Auth::attempt($email, $password)) {
            SecurityEventService::record($request, 'LOGIN_FAILURE', null, ['metadata' => ['reason' => 'credentials_not_verified']]);
            Session::put('_errors', ['email' => 'The supplied credentials could not be verified.']);
            Response::redirect('/login');
        }

        SecurityEventService::record($request, 'LOGIN_SUCCESS', (int) Auth::user()['id']);

        Session::forget('_old');
        Session::flash('success', 'Welcome back.');
        Response::redirect('/dashboard');
    }

    public function showRegister(Request $request): never
    {
        Response::view('auth/register', ['title' => 'Create account']);
    }

    public function register(Request $request): never
    {
        $name = trim((string) $request->input('name'));
        $email = strtolower(trim((string) $request->input('email')));
        $password = (string) $request->input('password');
        $confirmation = (string) $request->input('password_confirmation');
        $validation = [];

        if (mb_strlen($name) < 2 || mb_strlen($name) > 100) {
            $validation['name'] = 'Name must contain between 2 and 100 characters.';
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190) {
            $validation['email'] = 'Enter a valid email address.';
        }
        if (strlen($password) < 12 || !preg_match('/[A-Za-z]/', $password) || !preg_match('/\d/', $password)) {
            $validation['password'] = 'Use at least 12 characters with letters and numbers.';
        }
        if ($password !== $confirmation) {
            $validation['password_confirmation'] = 'Passwords do not match.';
        }

        Session::put('_old', ['name' => $name, 'email' => $email]);
        if ($validation !== []) {
            SecurityEventService::record($request, 'INVALID_REQUEST', null, ['target_type' => 'registration', 'metadata' => ['validation_fields' => array_keys($validation)]]);
            Session::put('_errors', $validation);
            Response::redirect('/register');
        }

        try {
            $account = User::create($name, $email, $password);
        } catch (PDOException $exception) {
            if ((string) $exception->getCode() === '23000') {
                Session::put('_errors', ['email' => 'An account already exists for this email address.']);
                Response::redirect('/register');
            }
            throw $exception;
        }

        Auth::login($account);
        SecurityEventService::record($request, 'REGISTRATION_SUCCESS', (int) $account['id']);
        Session::forget('_old');
        Session::flash('success', 'Your CHIMERA CLOUD account is ready.');
        Response::redirect('/dashboard');
    }

    public function logout(Request $request): never
    {
        $account = Auth::user();
        SecurityEventService::record($request, 'LOGOUT', $account === null ? null : (int) $account['id']);
        Auth::logout();
        Response::redirect('/');
    }
}
