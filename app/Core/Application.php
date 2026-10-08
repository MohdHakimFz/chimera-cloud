<?php

declare(strict_types=1);

namespace App\Core;

use Throwable;
use App\Services\SecurityEventService;
use App\Security\TransportSecurity;

final class Application
{
    private Router $router;

    public function __construct()
    {
        $this->router = new Router();
    }

    public function router(): Router
    {
        return $this->router;
    }

    public function run(): void
    {
        $request = Request::capture();
        $redirect=TransportSecurity::productionRedirect($_SERVER,$request->path());
        if($redirect!==null){header('Location: '.$redirect,true,308);return;}
        try {
            $this->router->dispatch($request);
        } catch (Throwable $exception) {
            SecurityEventService::record($request, 'SECURITY_RELEVANT_APPLICATION_ERROR');
            error_log(sprintf('[%s] %s in %s:%d', $exception::class, $exception->getMessage(), $exception->getFile(), $exception->getLine()));

            if ($request->isApi()) {
                Response::json(['error' => ['code' => 'SERVER_ERROR', 'message' => 'The request could not be completed.']], 500);
            }

            if (strtolower((string) env('APP_ENV', 'production')) !== 'production' && env_bool('APP_DEBUG', false)) {
                http_response_code(500);
                echo '<pre>' . e((string) $exception) . '</pre>';
                return;
            }

            Response::view('errors/500', [], 500);
        }
    }
}
