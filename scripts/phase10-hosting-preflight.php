<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/bootstrap/app.php';

use App\Services\HostingCapabilityInspector;
use App\Services\ProductionSecurityValidator;

$capabilities = HostingCapabilityInspector::inspect();
$readiness = ProductionSecurityValidator::evaluate([], [], true);

echo 'CHIMERA PHASE 10 HOSTING PREFLIGHT' . PHP_EOL;
echo 'CAPABILITY STATUS: ' . $capabilities['status'] . PHP_EOL;
foreach ($capabilities['checks'] as $check) {
    echo '[' . $check['status'] . '] ' . $check['label'] . ' - ' . $check['detail'] . PHP_EOL;
}
echo 'CAPABILITY SUMMARY: '
    . $capabilities['summary']['verified'] . ' VERIFIED, '
    . $capabilities['summary']['hosting_dependent'] . ' HOSTING-DEPENDENT, '
    . $capabilities['summary']['blocked'] . ' BLOCKED, '
    . $capabilities['summary']['not_applicable'] . ' NOT APPLICABLE' . PHP_EOL;
echo 'DEPLOYMENT MODE: ' . $readiness['mode'] . PHP_EOL;
echo 'READINESS GATE: ' . $readiness['gate'] . PHP_EOL;
echo 'READINESS SUMMARY: '
    . $readiness['summary']['pass'] . ' PASS, '
    . $readiness['summary']['warning'] . ' WARNING, '
    . $readiness['summary']['fail'] . ' FAIL' . PHP_EOL;
echo 'Secret values are intentionally omitted.' . PHP_EOL;

exit($capabilities['status'] === 'BLOCKED' || $readiness['status'] === 'FAIL' ? 1 : 0);
