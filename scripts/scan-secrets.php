<?php
declare(strict_types=1);
$root=dirname(__DIR__);require $root.'/bootstrap/app.php';$findings=App\Services\RepositorySecretScanner::scan($root);
if($findings===[]){echo"[PASS] Repository secret scan found no high-confidence committed secrets.\n";exit(0);}foreach($findings as$finding)echo'[FAIL] '.$finding['file'].' / '.$finding['category'].PHP_EOL;exit(1);
