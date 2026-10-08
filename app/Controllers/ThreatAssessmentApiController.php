<?php
declare(strict_types=1);
namespace App\Controllers;
use App\Core\Request;use App\Core\Response;use App\Models\SecuritySession;
final class ThreatAssessmentApiController
{
    public function sessions(Request $request): never { $data=SecuritySession::all();Response::json(['data'=>$data,'meta'=>['count'=>count($data)]]); }
    public function session(Request $request): never { $data=SecuritySession::find((int)$request->route('id',0));if($data===null)Response::json(['error'=>['code'=>'NOT_FOUND','message'=>'Resource not found.']],404);Response::json(['data'=>$data]); }
    public function summary(Request $request): never { Response::json(['data'=>SecuritySession::summary()]); }
}
