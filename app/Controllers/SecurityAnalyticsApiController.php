<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Services\EvidenceExportService;
use App\Services\SecurityAnalyticsService;

final class SecurityAnalyticsApiController
{
    public function summary(Request $request): never { Response::json(['data'=>SecurityAnalyticsService::dashboard(self::validatedFilters($request))]); }
    public function timeline(Request $request): never { $limit=self::limit($request);$data=SecurityAnalyticsService::timeline(self::validatedFilters($request),$limit);Response::json(['data'=>$data,'meta'=>['count'=>count($data),'limit'=>$limit]]); }
    public function session(Request $request): never { $data=SecurityAnalyticsService::sessionAnalysis((int)$request->route('id',0));if($data===null)Response::json(['error'=>['code'=>'NOT_FOUND','message'=>'Resource not found.']],404);Response::json(['data'=>$data]); }
    public function lab(Request $request): never { Response::json(['data'=>SecurityAnalyticsService::labEvaluation(self::validatedFilters($request))]); }
    public function export(Request $request): never
    {
        $type=is_scalar($request->query('type'))?(string)$request->query('type'):'';$format=is_scalar($request->query('format','json'))?(string)$request->query('format','json'):'json';$sessionValue=$request->query('session_id');$sessionId=null;if($sessionValue!==null){$validated=filter_var($sessionValue,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);if($validated===false)Response::json(['error'=>['code'=>'INVALID_EXPORT','message'=>'Unsupported export request.']],422);$sessionId=(int)$validated;}
        $filters=self::validatedExportFilters($request);
        if(SecurityAnalyticsService::exportFilterErrors($type,$filters)!==[])Response::json(['error'=>['code'=>'INVALID_FILTER','message'=>'The requested filters are not valid for this export type.']],422);
        $export=EvidenceExportService::generate($type,$format,$filters,$sessionId===null?null:(int)$sessionId);
        if($export===null)Response::json(['error'=>['code'=>'INVALID_EXPORT','message'=>'Unsupported export request.']],422);
        http_response_code(200);header('Content-Type: '.$export['content_type']);header('Content-Disposition: attachment; filename="chimera-'.$type.'-'.gmdate('Ymd-His').'.'.$export['extension'].'"');header('Cache-Control: private, no-store, max-age=0');header('X-Content-Type-Options: nosniff');echo $export['body'];exit;
    }
    private static function validatedFilters(Request $request):array{$filters=SecurityAnalyticsService::filters($request->allQuery());if($filters['errors']!==[])Response::json(['error'=>['code'=>'INVALID_FILTER','message'=>'One or more analytics filters are invalid.','details'=>$filters['errors']]],422);return$filters;}
    private static function validatedExportFilters(Request $request):array{$query=$request->allQuery();unset($query['type'],$query['format'],$query['session_id']);if(array_key_exists('event_type',$query)){$query['type']=$query['event_type'];unset($query['event_type']);}$filters=SecurityAnalyticsService::filters($query);if($filters['errors']!==[])Response::json(['error'=>['code'=>'INVALID_FILTER','message'=>'One or more analytics filters are invalid.','details'=>$filters['errors']]],422);return$filters;}
    private static function limit(Request $request):int{$limit=filter_var($request->query('limit',100),FILTER_VALIDATE_INT,['options'=>['min_range'=>1,'max_range'=>SecurityAnalyticsService::MAX_TIMELINE]]);return$limit===false?100:(int)$limit;}
}
