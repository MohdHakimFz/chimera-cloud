<?php
declare(strict_types=1);
namespace App\Controllers;
use App\Core\Request;use App\Core\Response;use App\Models\SecuritySession;use App\Services\ThreatScoringService;
final class ThreatAssessmentController
{
    public function index(Request $request): never { Response::view('security/threats',['title'=>'Threat Assessment','summary'=>SecuritySession::summary(),'sessions'=>SecuritySession::all(),'rules'=>ThreatScoringService::rules()]); }
    public function show(Request $request): never { $session=SecuritySession::find((int)$request->route('id',0));if($session===null)Response::abort(404,'The requested security session could not be found.');Response::view('security/threat-show',['title'=>'Security Session','session'=>$session]); }
}
