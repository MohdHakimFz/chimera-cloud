<?php
declare(strict_types=1);
$root=dirname(__DIR__);require $root.'/app/Core/Env.php';App\Core\Env::load($root.'/.env');
if((string)getenv('TEST_DB_DATABASE')!=='chimera_test'){echo"[FAIL] TEST_DB_DATABASE must be exactly chimera_test.\n";exit(1);}$testUser=(string)getenv('TEST_DB_USERNAME');$testPassword=(string)getenv('TEST_DB_PASSWORD');putenv('DB_DATABASE=chimera_test');$_ENV['DB_DATABASE']='chimera_test';putenv('DB_USERNAME='.$testUser);$_ENV['DB_USERNAME']=$testUser;putenv('DB_PASSWORD='.$testPassword);$_ENV['DB_PASSWORD']=$testPassword;
$app=require $root.'/bootstrap/app.php';
use App\Core\Database;use App\Services\EvidenceExportService;use App\Services\SecurityAnalyticsService;
$db=Database::connection();$meta=$db->query('SELECT DATABASE() db,@@port port,CURRENT_USER() usr')->fetch();if($meta['db']!=='chimera_test'||(int)$meta['port']!==3308||!str_starts_with($meta['usr'],'chimera_test_app@')){echo"[FAIL] Unsafe Phase 8 integration target.\n";exit(1);}
$starts=[];foreach(['security_events','security_sessions','security_score_contributors','honeytoken_events','vulnerability_state_changes','vulnerability_modules']as$t)$starts[$t]=(int)$db->query("SELECT COALESCE(MAX(id),0) FROM {$t}")->fetchColumn();
$p=0;$f=0;$check=function(bool $ok,string $label)use(&$p,&$f):void{echo($ok?'[PASS] ':'[FAIL] ').$label.PHP_EOL;$ok?$p++:$f++;};
$insertSession=$db->prepare("INSERT INTO security_sessions(session_identifier,source_hash,user_agent_hash,threat_score,classification,request_count,first_seen_at,last_seen_at)VALUES(UUID(),:source,REPEAT('b',64),:score,:level,:requests,:first,:last)");
$insertEvent=$db->prepare('INSERT INTO security_events(security_session_id,event_type,source_safe_identifier,endpoint,http_method,severity,risk_delta,description,metadata_json,created_at)VALUES(:sid,:type,REPEAT(\'a\',64),:endpoint,\'GET\',:severity,:delta,:description,:metadata,:created)');
$insertContributor=$db->prepare('INSERT INTO security_score_contributors(security_session_id,rule_code,label,risk_delta,created_at)VALUES(:sid,:rule,:label,:delta,:created)');
$ids=[];
try{
 $insertSession->execute(['source'=>str_repeat('1',64),'score'=>70,'level'=>'HIGH','requests'=>7,'first'=>'2037-01-10 10:00:00','last'=>'2037-01-10 10:04:00']);$s1=(int)$db->lastInsertId();
 $insertSession->execute(['source'=>str_repeat('2',64),'score'=>0,'level'=>'LOW','requests'=>1,'first'=>'2037-01-10 11:00:00','last'=>'2037-01-10 11:00:00']);$s2=(int)$db->lastInsertId();
 $insertSession->execute(['source'=>str_repeat('3',64),'score'=>5,'level'=>'LOW','requests'=>2,'first'=>'2037-01-10 12:00:00','last'=>'2037-01-10 12:00:30']);$s3=(int)$db->lastInsertId();
 $add=function(int $sid,string $type,string $time,string $category,string $severity='INFO',array $extra=[])use($insertEvent,$db,&$ids):int{$metadata=['category'=>$category,'outcome'=>'SUCCESS',...$extra];$insertEvent->execute(['sid'=>$sid?:null,'type'=>$type,'endpoint'=>'/phase8-fixture','severity'=>$severity,'delta'=>0,'description'=>'Phase 8 deterministic fixture.','metadata'=>json_encode($metadata,JSON_THROW_ON_ERROR),'created'=>$time]);$id=(int)$db->lastInsertId();$ids[]=$id;return$id;};
 $contribute=function(int $sid,int $event,string $rule,int $delta,string $time)use($insertContributor):void{$insertContributor->execute(['sid'=>$sid,'rule'=>$rule,'label'=>"Event #{$event}: deterministic fixture",'delta'=>$delta,'created'=>$time]);};
 $e1=$add($s1,'LOGIN_FAILURE','2037-01-10 10:00:00','AUTHENTICATION','MEDIUM');$contribute($s1,$e1,'LOGIN_FAILURE',5,'2037-01-10 10:00:00');
 $e2=$add($s1,'ROLE_ACCESS_DENIED','2037-01-10 10:01:00','AUTHORIZATION','MEDIUM');$contribute($s1,$e2,'ROLE_ACCESS_DENIED',10,'2037-01-10 10:01:00');
 $add($s1,'DECEPTION_PROFILE_SELECTED','2037-01-10 10:01:30','DECEPTION','INFO',['selected_profile'=>'MEDIUM','previous_profile'=>'LOW']);
 $e4=$add($s1,'DECOY_ACCESSED','2037-01-10 10:02:00','DECEPTION','MEDIUM',['target_identifier'=>'DEC-P8','deception_profile'=>'MEDIUM']);$contribute($s1,$e4,'DECOY_ACCESSED',20,'2037-01-10 10:02:00');
 $add($s1,'DECEPTION_PROFILE_CHANGED','2037-01-10 10:02:30','DECEPTION','INFO',['selected_profile'=>'HIGH','previous_profile'=>'MEDIUM']);
 $add($s1,'ADAPTIVE_DECOY_RENDERED','2037-01-10 10:03:00','DECEPTION','INFO',['selected_profile'=>'HIGH']);
 $e7=$add($s1,'HONEYTOKEN_TRIGGERED','2037-01-10 10:04:00','DECEPTION','HIGH',['target_identifier'=>'HT-P8','deception_profile'=>'HIGH']);$contribute($s1,$e7,'HONEYTOKEN_TRIGGERED',35,'2037-01-10 10:04:00');
 $add($s2,'LOGIN_SUCCESS','2037-01-10 11:00:00','AUTHENTICATION','INFO');
 $add($s3,'LOGIN_SUCCESS','2037-01-10 12:00:00','AUTHENTICATION','INFO');$e10=$add($s3,'LOGIN_FAILURE','2037-01-10 12:00:30','AUTHENTICATION','MEDIUM');$contribute($s3,$e10,'LOGIN_FAILURE',5,'2037-01-10 12:00:30');
 $moduleId=(int)$db->query("SELECT id FROM vulnerability_modules WHERE vulnerability_identifier='CHIM-VULN-002'")->fetchColumn();
 if($moduleId===0){$db->exec("INSERT INTO vulnerability_modules(vulnerability_identifier,name,description,affected_component,expected_attack_surface,learning_objective,expected_impact,mitigation,state,is_active)VALUES('CHIM-VULN-002','Controlled SQL Injection','Synthetic Phase 8 fixture.','SQL Injection','/lab/sqli','Compare vulnerable and prepared queries.','Synthetic rows only.','Use prepared statements.','VULNERABLE',1)");$moduleId=(int)$db->lastInsertId();}
 $add(0,'LAB_VULNERABILITY_INTERACTION','2037-01-10 13:00:00','LAB','INFO',['module_identifier'=>'CHIM-VULN-002','module_state'=>'VULNERABLE','result_count'=>3,'lab_authorized'=>true]);
 $add(0,'LAB_REMEDIATED_TEST','2037-01-10 13:01:00','LAB','INFO',['module_identifier'=>'CHIM-VULN-002','module_state'=>'REMEDIATED','result_count'=>0,'lab_authorized'=>true]);
 if($moduleId>0){$stmt=$db->prepare("INSERT INTO vulnerability_state_changes(vulnerability_module_id,changed_by_user_id,from_state,to_state,reason,created_at)VALUES(:mid,NULL,'VULNERABLE','REMEDIATED','Phase 8 deterministic evidence fixture.','2037-01-10 13:00:30')");$stmt->execute(['mid'=>$moduleId]);}
 $filters=SecurityAnalyticsService::filters(['date_from'=>'2037-01-10','date_to'=>'2037-01-10']);$data=SecurityAnalyticsService::dashboard($filters);
 $check($data['events']['total']===12,'Total event count is deterministic');
 $byType=array_column($data['events']['by_type'],'total','label');$check(($byType['LOGIN_FAILURE']??0)===2&&($byType['DECOY_ACCESSED']??0)===1,'Event-type grouping is correct');
 $bySeverity=array_column($data['events']['by_severity'],'total','label');$check(($bySeverity['HIGH']??0)===1&&($bySeverity['MEDIUM']??0)===4,'Severity grouping is correct');
 $byCategory=array_column($data['events']['by_category'],'total','label');$check(($byCategory['LAB']??0)===2&&($byCategory['DECEPTION']??0)===5,'Category grouping keeps LAB separate');
 $check($data['sessions']['total']===3&&$data['sessions']['by_level']['HIGH']===1&&$data['sessions']['by_level']['LOW']===2,'Threat-level distribution is correct');
 $contributors=array_column($data['sessions']['contributors'],'total','label');$check(($contributors['LOGIN_FAILURE']??0)===2&&($contributors['HONEYTOKEN_TRIGGERED']??0)===1,'Contributor frequency is correct');
 $analysis=SecurityAnalyticsService::sessionAnalysis($s1);$check($analysis!==null&&$analysis['assessment']['reconstructed_score']===70&&$analysis['assessment']['integrity_status']==='CONSISTENT','Score reconstructs from persisted contributors');
 $check($analysis['detection']['detection_latency_seconds']===0,'First-event positive signal produces zero detection latency');
 $check($analysis['detection']['time_to_deception_seconds']===120,'Time to deception uses first genuine decoy access');
 $check($analysis['detection']['time_to_honeytoken_seconds']===240,'Time to honeytoken uses first trigger');
 $analysis2=SecurityAnalyticsService::sessionAnalysis($s2);$check($analysis2['detection']['detection_latency_seconds']===null&&$analysis2['detection']['time_to_deception_seconds']===null,'Missing positive/deception evidence remains N/A');
 $analysis3=SecurityAnalyticsService::sessionAnalysis($s3);$check($analysis3['detection']['detection_latency_seconds']===30,'Later first contributor produces expected detection latency');
 $check($data['detection']['detection_latency']['measurable_sessions']===2&&$data['detection']['detection_latency']['average_seconds']===15.0,'Aggregate detection latency excludes N/A sessions');
 $check($data['deception']['decoy_interactions']===1&&$data['deception']['honeytoken_triggers']===1&&$data['deception']['adaptive_renders']===1,'Deception/adaptive counts are deterministic');
 $check($data['events']['lab_total']===2&&$data['detection']['detection_latency']['measurable_sessions']===2,'LAB events do not inflate operational detection metrics');
 $sqlModule=array_values(array_filter($data['lab']['modules'],static fn(array $m):bool=>$m['module_identifier']==='CHIM-VULN-002'))[0];$check($sqlModule['vulnerable_tests']===1&&$sqlModule['remediated_tests']===1,'Lab vulnerable/remediated comparison is evidence-backed');
 $eventIds=array_column($analysis['timeline'],'event_id');$check(count($eventIds)===count(array_unique($eventIds))&&$analysis['timeline'][0]['contributors'][0]['rule_code']==='LOGIN_FAILURE','Timeline is chronological with contributors attached, not duplicated');
 $profileOnly=SecurityAnalyticsService::dashboard(SecurityAnalyticsService::filters(['date_from'=>'2037-01-10','date_to'=>'2037-01-10','profile'=>'HIGH']));$check($profileOnly['events']['total']===3,'Adaptive profile filter is parameterized and exact');
 $bad=SecurityAnalyticsService::dashboard(SecurityAnalyticsService::filters(['type'=>"LOGIN_FAILURE' OR 1=1 --",'date_from'=>'2037-01-10','date_to'=>'2037-01-10']));$check($bad['filters']['errors']!==[]&&$bad['events']['total']===0,'Malformed filter fails closed without broadening results');
 $json=EvidenceExportService::generate('session_evidence','json',SecurityAnalyticsService::filters([]),$s1);$decoded=json_decode($json['body'],true);$check(is_array($decoded)&&$decoded['data'][0]['session']['evidence_id']!==null,'JSON evidence export is valid and contains stable identifiers');
 $csv=EvidenceExportService::generate('security_events','csv',$filters);$check(str_contains($csv['content_type'],'text/csv')&&str_contains($csv['body'],'evidence_id'),'CSV evidence export has expected content type and headers');
 $check(!preg_match('/password_hash|session_identifier|token_hash|storage_name|DB_PASSWORD/i',$json['body'].$csv['body']),'Exports exclude sensitive field names');
 $snapBefore=[(int)$db->query("SELECT threat_score FROM security_sessions WHERE id={$s1}")->fetchColumn(),(int)$db->query("SELECT COUNT(*) FROM security_score_contributors WHERE security_session_id={$s1}")->fetchColumn(),(string)$db->query("SELECT state FROM vulnerability_modules WHERE id={$moduleId}")->fetchColumn()];SecurityAnalyticsService::dashboard($filters);$snapAfter=[(int)$db->query("SELECT threat_score FROM security_sessions WHERE id={$s1}")->fetchColumn(),(int)$db->query("SELECT COUNT(*) FROM security_score_contributors WHERE security_session_id={$s1}")->fetchColumn(),(string)$db->query("SELECT state FROM vulnerability_modules WHERE id={$moduleId}")->fetchColumn()];$check($snapBefore===$snapAfter,'Analytics execution is read-only for scores, contributors, and lab state');
}catch(Throwable $e){$f++;echo'[FAIL] Phase 8 integration exception: '.$e->getMessage().PHP_EOL;}
finally{$db->exec("DELETE FROM vulnerability_state_changes WHERE id>{$starts['vulnerability_state_changes']}");$db->exec("DELETE FROM security_events WHERE id>{$starts['security_events']}");$db->exec("DELETE FROM security_sessions WHERE id>{$starts['security_sessions']}");$db->exec("DELETE FROM vulnerability_modules WHERE id>{$starts['vulnerability_modules']}");}
$check((int)$db->query("SELECT COUNT(*) FROM security_events WHERE id>{$starts['security_events']}")->fetchColumn()===0&&(int)$db->query("SELECT COUNT(*) FROM security_sessions WHERE id>{$starts['security_sessions']}")->fetchColumn()===0,'Integration fixtures are fully cleaned from chimera_test');
echo"\n{$p} checks passed, {$f} failed.\n";exit($f===0?0:1);
