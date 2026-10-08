<?php
declare(strict_types=1);
$app=require dirname(__DIR__).'/bootstrap/app.php';
$result=App\Services\ProductionSecurityValidator::evaluate([],[],true);
echo 'CHIMERA PRE-DEPLOYMENT READINESS'.PHP_EOL;
echo 'MODE: '.$result['mode'].PHP_EOL.'GATE: '.$result['gate'].PHP_EOL;
foreach($result['checks']as$check)echo '['.$check['status'].'] '.$check['category'].' / '.$check['label'].' - '.$check['detail'].PHP_EOL;
echo 'SUMMARY: '.$result['summary']['pass'].' PASS, '.$result['summary']['warning'].' WARNING, '.$result['summary']['fail'].' FAIL'.PHP_EOL;
exit($result['status']==='FAIL'?1:0);
