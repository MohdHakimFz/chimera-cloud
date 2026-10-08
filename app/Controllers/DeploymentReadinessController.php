<?php
declare(strict_types=1);
namespace App\Controllers;
use App\Core\Request;use App\Core\Response;use App\Services\ProductionSecurityValidator;
final class DeploymentReadinessController
{
    public function index(Request $request): never
    {
        Response::view('security/deployment-readiness',['title'=>'Deployment Readiness','readiness'=>ProductionSecurityValidator::evaluate([], $_SERVER, true)]);
    }
}
