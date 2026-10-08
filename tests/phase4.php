<?php
declare(strict_types=1);
$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';
use App\Security\SecurityEventTaxonomy;
use App\Services\HoneytokenService;

$passes=0;$failures=0;
$check=static function(bool $ok,string $label)use(&$passes,&$failures):void{echo($ok?'[PASS] ':'[FAIL] ').$label."\n";$ok?$passes++:$failures++;};
$source=static fn(string $path):string=>(string)file_get_contents($root.'/'.$path);
$routes=$source('routes/web.php');$decoy=$source('app/Services/DecoyService.php');$honey=$source('app/Services/HoneytokenService.php');$honeyModel=$source('app/Models/Honeytoken.php');$controller=$source('app/Controllers/DecoyController.php');
$check(SecurityEventTaxonomy::definition('DECOY_ACCESSED')['category']==='DECEPTION','Decoy event extends the centralized taxonomy');
$check(SecurityEventTaxonomy::definition('HONEYTOKEN_TRIGGERED')['severity']==='HIGH','Honeytoken severity is deterministic without scoring');
$check(HoneytokenService::material('HT-API-001')==='CHM_HONEY_HT_API_001','Honeytoken material uses the CHIMERA-only format');
$check((bool)preg_match('/\ACHM_HONEY_[A-Z0-9_]+\z/',HoneytokenService::material('HT-BACKUP-001')),'Honeytoken material is synthetically namespaced');
$check(str_contains($decoy,'DecoyEndpoint::findActiveByPath'),'Decoy resolution requires an active configured record');
$check(str_contains($decoy,'SecurityEventService::record'),'Decoy access uses the Phase 3 telemetry service');
$check(str_contains($honey,'Honeytoken::findActiveByMaterial')&&str_contains($honeyModel,"hash('sha256'"),'Honeytoken lookup validates registry hashes');
$check(str_contains($honey,'honeytoken_events'),'Honeytoken triggers link to a security event');
$check(!str_contains($decoy,'Document::')&&!str_contains($honey,'Document::'),'Deception services cannot query real documents');
$check(!str_contains($decoy,'Auth::login')&&!str_contains($honey,'Auth::login'),'Deception services cannot authenticate accounts');
$check(str_contains($routes,"'/admin-old'")&&str_contains($routes,"'/internal'")&&str_contains($routes,"'/api/debug'"),'Static decoy routes are explicit');
$check(str_contains($routes,"'/api/debug/verify'"),'Deterministic honeytoken trigger route is explicit');
$check(substr_count($routes,"new RequireRole(['security_admin'])")>=10,'Deception dashboard and APIs require exact Security Admin role');
$check(!preg_match('/threat_score\s*[+\-=]|risk_delta\s*[+\-]|automatic.?block|shell_exec|\beval\s*\(/i',$decoy.$honey.$controller),'No scoring, blocking, exploitation, or command execution exists');
$check(!str_contains($controller,'getenv(')&&!str_contains($controller,'$_ENV'),'Decoy responses cannot expose environment configuration');
echo"\n{$passes} Phase 4 checks passed, {$failures} failed.\n";exit($failures===0?0:1);
