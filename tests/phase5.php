<?php
declare(strict_types=1);
$root=dirname(__DIR__);require $root.'/bootstrap/app.php';
use App\Services\ThreatScoringService;
$p=0;$f=0;$check=static function(bool $ok,string $label)use(&$p,&$f):void{echo($ok?'[PASS] ':'[FAIL] ').$label."\n";$ok?$p++:$f++;};
$weights=['LOGIN_FAILURE'=>5,'ACCESS_DENIED'=>3,'ROLE_ACCESS_DENIED'=>10,'OWNERSHIP_ACCESS_DENIED'=>12,'CSRF_REJECTED'=>12,'DOCUMENT_UPLOAD_REJECTED'=>5,'DOCUMENT_INTEGRITY_FAILURE'=>20,'DECOY_ACCESSED'=>20,'HONEYTOKEN_TRIGGERED'=>35,'SECURITY_RELEVANT_APPLICATION_ERROR'=>10];
foreach($weights as $type=>$weight)$check(ThreatScoringService::weight($type)===$weight,"{$type} weight is {$weight}");
$check(ThreatScoringService::weight('LOGIN_SUCCESS')===0,'Benign success has zero weight');
$check(ThreatScoringService::bounded(-10)===0&&ThreatScoringService::bounded(150)===100,'Score is bounded from 0 to 100');
$check(ThreatScoringService::classification(0)==='LOW'&&ThreatScoringService::classification(19)==='LOW','LOW threshold is 0-19');
$check(ThreatScoringService::classification(20)==='MEDIUM'&&ThreatScoringService::classification(44)==='MEDIUM','MEDIUM threshold is 20-44');
$check(ThreatScoringService::classification(45)==='HIGH'&&ThreatScoringService::classification(74)==='HIGH','HIGH threshold is 45-74');
$check(ThreatScoringService::classification(75)==='CRITICAL'&&ThreatScoringService::classification(100)==='CRITICAL','CRITICAL threshold is 75-100');
$session=(string)file_get_contents($root.'/app/Services/SecuritySessionService.php');$routes=(string)file_get_contents($root.'/routes/web.php');
$check(str_contains($session,'FOR UPDATE')&&str_contains($session,'security_session_id IS NULL'),'Correlation uses locking and an unprocessed-event guard');
$check(str_contains($session,'WINDOW_MINUTES = 30'),'Security-session window is exactly 30 minutes');
$check(substr_count($routes,"new RequireRole(['security_admin'])")>=15,'Assessment views and APIs require exact Security Admin role');
$check(!preg_match('/block|activate.*decoy|disable.*account|update users set role/i',(string)file_get_contents($root.'/app/Services/ThreatScoringService.php')),'Scoring service contains no automatic response behavior');
echo"\n{$p} Phase 5 checks passed, {$f} failed.\n";exit($f===0?0:1);
