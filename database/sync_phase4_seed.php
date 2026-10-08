<?php
declare(strict_types=1);
use App\Core\Database;
$app = require dirname(__DIR__) . '/bootstrap/app.php';
$database = Database::connection();
$connection = $database->query('SELECT DATABASE() AS database_name, @@port AS server_port, CURRENT_USER() AS authenticated_user')->fetch();
if (($connection['database_name'] ?? '') !== 'chimera' || (int)($connection['server_port'] ?? 0) !== 3308 || !str_starts_with((string)($connection['authenticated_user'] ?? ''), 'chimera_app@')) {
    throw new RuntimeException('Phase 4 seed synchronization refused outside chimera on port 3308 with chimera_app.');
}
$tokens = ['HT-BACKUP-001' => 'CHM_HONEY_HT_BACKUP_001', 'HT-API-001' => 'CHM_HONEY_HT_API_001'];
$statement = $database->prepare('UPDATE honeytokens SET token_hash = :token_hash WHERE token_identifier = :token_identifier');
foreach ($tokens as $identifier => $material) {
    $statement->execute(['token_hash' => hash('sha256', $material), 'token_identifier' => $identifier]);
    if ($statement->rowCount() > 1) throw new RuntimeException('Unexpected honeytoken seed row count.');
}
echo "[PASS] Phase 4 synthetic honeytoken hashes synchronized in chimera.\n";
