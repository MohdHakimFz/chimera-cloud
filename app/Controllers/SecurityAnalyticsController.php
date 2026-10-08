<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Request;
use App\Core\Response;
use App\Security\SecurityEventTaxonomy;
use App\Services\EvidenceExportService;
use App\Services\SecurityAnalyticsService;

final class SecurityAnalyticsController
{
    public function index(Request $request): never
    {
        $filters=SecurityAnalyticsService::filters($request->allQuery());
        $exportUrls=[];
        foreach(EvidenceExportService::TYPES as$type){$query=['type'=>$type,'format'=>'json'];foreach(SecurityAnalyticsService::exportFilterKeys($type)as$key)if(($filters[$key]??'')!=='')$query[$key==='type'?'event_type':$key]=$filters[$key];$exportUrls[$type]=url('/api/security/analytics/export?'.http_build_query($query));}
        Response::view('security/analytics',['title'=>'Security Analytics','analytics'=>SecurityAnalyticsService::dashboard($filters),'eventTypes'=>SecurityEventTaxonomy::eventTypes(),'categories'=>SecurityEventTaxonomy::categories(),'severities'=>SecurityEventTaxonomy::severities(),'exportTypes'=>EvidenceExportService::TYPES,'exportUrls'=>$exportUrls]);
    }

    public function session(Request $request): never
    {
        $analysis=SecurityAnalyticsService::sessionAnalysis((int)$request->route('id',0));
        if($analysis===null)Response::abort(404,'The requested security-session evidence could not be found.');
        Response::view('security/analytics-session',['title'=>'Session Evidence','analysis'=>$analysis]);
    }
}
