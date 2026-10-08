<?php

declare(strict_types=1);

namespace App\Lab;

use App\Core\Response;

final class LabResponse
{
    public static function html(string $view, array $data = [], int $status = 200): never
    {
        header("Content-Security-Policy: sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'");
        header('Referrer-Policy: no-referrer');
        header('X-CHIMERA-Lab: controlled-enabled');
        header('Cache-Control: no-store');
        Response::standaloneView($view, $data, $status);
    }
}
