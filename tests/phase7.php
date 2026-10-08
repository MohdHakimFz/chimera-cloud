<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap/app.php';

use App\Lab\ControlledLabService;
use App\Security\SecurityEventTaxonomy;
use App\Services\ThreatScoringService;

$passes=0;$failures=0;
$check=static function(bool $ok,string $label)use(&$passes,&$failures):void{echo($ok?'[PASS] ':'[FAIL] ').$label."\n";$ok?$passes++:$failures++;};
$env=(string)file_get_contents($root.'/.env.example');
$routes=(string)file_get_contents($root.'/routes/web.php');
$middleware=(string)file_get_contents($root.'/app/Middleware/RequireLabEnabled.php');
$service=(string)file_get_contents($root.'/app/Lab/ControlledLabService.php');
$response=(string)file_get_contents($root.'/app/Lab/LabResponse.php');
$stateController=(string)file_get_contents($root.'/app/Controllers/LabManagementController.php');
$definitions=ControlledLabService::definitions();

$check(str_contains($env,'VULNERABILITY_LAB_ENABLED=false'),'Lab environment switch defaults to false');
$check(str_contains($middleware,"env_bool('VULNERABILITY_LAB_ENABLED', false)")&&str_contains($middleware,'Response::abort(404'),'Disabled lab middleware returns safe 404');
foreach(['/lab','/lab/robots.txt','/lab/sqli','/lab/idor','/lab/xss'] as $path){$check(str_contains($routes,"'{$path}'")&&str_contains($routes,'RequireLabEnabled::class'),"Lab route {$path} is explicitly gated");}
$check(array_keys($definitions)===['CHIM-VULN-001','CHIM-VULN-002','CHIM-VULN-003'],'Registry allowlist defines exactly three controlled modules');
$check(str_contains($service,"AS lab_records")&&str_contains($service,"WHERE lab_code = '{\$input}'"),'Vulnerable SQL mode is confined to an inline synthetic derived dataset');
$check(str_contains($service,'WHERE lab_code = :lab_code')&&str_contains($service,"\$state === 'REMEDIATED'"),'Remediated SQL mode uses a prepared parameter');
$check(str_contains($service,"'union'")&&str_contains($service,"';'")&&str_contains($service,"'outfile'"),'SQL lab grammar rejects union, stacked, and file primitives');
$check(!preg_match('/\bFROM\s+(users|documents|user_activity|security_events|security_sessions)\b/i',$service),'Lab service has no query path to real or security tables');
$check(str_contains($service,"'LAB-1001'")&&str_contains($service,"'LAB-2001'")&&!str_contains($service,'App\\Models\\Document'),'IDOR module uses only LAB-prefixed static objects');
$check(str_contains($response,'sandbox allow-scripts')&&str_contains($response,"connect-src 'none'")&&!str_contains($response,'allow-same-origin'),'XSS response uses an opaque-origin CSP sandbox with no network connection');
$check(str_contains((string)file_get_contents($root.'/resources/views/lab/xss.php'),"\$module['state']==='VULNERABLE'")&&str_contains((string)file_get_contents($root.'/resources/views/lab/xss.php'),'e($reflection)'),'XSS view provides vulnerable and escaped comparison states');
$check(str_contains($routes,"post('/security/lab/modules/{id}/state")&&str_contains($routes,'VerifyCsrf::class'),'Lab state mutation is POST-only and CSRF protected');
$check(str_contains($routes,"new RequireRole(['security_admin'])")&&str_contains($stateController,'VulnerabilityModule::changeState'),'Only Security Admin route can invoke allowlisted state management');
foreach(['LAB_MODULE_ACCESSED','LAB_VULNERABILITY_INTERACTION','LAB_REMEDIATED_TEST','LAB_MODULE_STATE_CHANGED'] as $event){$check(SecurityEventTaxonomy::definition($event)['category']==='LAB'&&ThreatScoringService::weight($event)===0,"{$event} is distinguishable zero-score telemetry");}
$eventService=(string)file_get_contents($root.'/app/Services/SecurityEventService.php');
$check(str_contains($eventService,"\$definition['category'] !== 'LAB'"),'LAB telemetry is excluded from operational security-session scoring');
$check(!str_contains($service,'AdaptiveDeceptionService')&&!str_contains($stateController,'AdaptiveDeceptionService'),'Lab state and behavior do not depend on adaptive deception');
$highRisk=preg_match('/shell_exec|passthru|proc_open|popen|eval\s*\(|include\s*\(|require\s*\(|curl_|file_put_contents|unlink\s*\(|fsockopen|stream_socket_client/i',$service.$stateController.$response);
$check($highRisk===0,'Lab implementation contains no shell, execution, file-write, SSRF, or destructive primitive');
$real='';foreach(['AuthController.php','DocumentController.php','ProfileController.php','ApiController.php','AdminController.php'] as $file)$real.=(string)file_get_contents($root.'/app/Controllers/'.$file);
$check(!str_contains($real,'App\\Lab')&&!str_contains($real,'VulnerabilityModule'),'Real application controllers do not import lab components');

echo"\n{$passes} Phase 7 checks passed, {$failures} failed.\n";exit($failures===0?0:1);
