<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;

final class HomeController
{
    public function index(Request $request): never
    {
        Response::view('home', ['title' => 'Secure document collaboration']);
    }

    public function about(Request $request): never
    {
        Response::view('about', ['title' => 'About']);
    }
}

