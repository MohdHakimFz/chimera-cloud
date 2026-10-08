<?php

declare(strict_types=1);

use App\Core\Database;

$app = require dirname(__DIR__) . '/bootstrap/app.php';
$database = Database::connection();
$connection = $database->query('SELECT DATABASE() database_name,@@port server_port,CURRENT_USER() authenticated_user')->fetch();
if (($connection['database_name'] ?? '') !== 'chimera' || (int)($connection['server_port'] ?? 0) !== 3308 || !str_starts_with((string)($connection['authenticated_user'] ?? ''), 'chimera_app@')) {
    throw new RuntimeException('Phase 7 registry synchronization refused outside chimera on port 3308 with chimera_app.');
}

$modules = [
    ['CHIM-VULN-001','Controlled Broken Object Authorization','Synthetic object lookup demonstrating missing versus enforced ownership.','/lab/idor','GET requests using LAB-prefixed synthetic object identifiers.','Compare predictable cross-object access with an owner-bound lookup.','Read-only exposure of another synthetic lab identity record.','Require the synthetic actor owner to match the requested lab object.'],
    ['CHIM-VULN-002','Controlled SQL Injection','Bounded SQL predicate demonstration over an inline synthetic derived dataset.','/lab/sqli','GET search input using a restricted non-stacked predicate grammar.','Compare string concatenation with a bound prepared parameter.','Read-only retrieval of additional inline synthetic rows.','Use a prepared statement and bind the exact archive code.'],
    ['CHIM-VULN-003','Controlled Reflected XSS','Non-persistent reflection inside a standalone opaque-origin CSP sandbox.','/lab/xss','GET input reflected only by the isolated lab response.','Compare raw reflection with contextual HTML escaping.','Script execution is confined to a sandboxed lab document with no same-origin access.','Encode reflected content with htmlspecialchars before rendering.'],
];
$statement = $database->prepare(
    "INSERT INTO vulnerability_modules
     (vulnerability_identifier,name,description,affected_component,expected_attack_surface,learning_objective,expected_impact,mitigation,state,is_active)
     VALUES (?,?,?,?,?,?,?,?,'VULNERABLE',1)
     ON DUPLICATE KEY UPDATE name=VALUES(name),description=VALUES(description),affected_component=VALUES(affected_component),expected_attack_surface=VALUES(expected_attack_surface),learning_objective=VALUES(learning_objective),expected_impact=VALUES(expected_impact),mitigation=VALUES(mitigation),is_active=1"
);
foreach ($modules as $module) {
    $statement->execute($module);
}
echo "[PASS] Phase 7 synthetic vulnerability registry synchronized without changing existing module states.\n";
