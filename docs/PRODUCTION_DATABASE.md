# Production Database

Use a dedicated MariaDB account for only the CHIMERA database. Never run the application as root and never grant global data or administrative privileges.

Example placeholders for an administrator to adapt manually:

```sql
CREATE DATABASE IF NOT EXISTS `chimera`
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'chimera_app'@'localhost'
  IDENTIFIED BY '<unique-password-from-a-password-manager>';

GRANT SELECT, INSERT, UPDATE, DELETE
  ON `chimera`.* TO 'chimera_app'@'localhost';
```

Schema import/migration must use a separate temporary administrative workflow. The runtime account should not receive CREATE, DROP, ALTER, INDEX, GRANT OPTION, FILE, SUPER, PROCESS, SHUTDOWN, CREATE USER, or RELOAD. Some shared hosts provide a generated username/host rather than `localhost`; this is HOSTING-DEPENDENT.

Phase 9 locally verified that `chimera_app`/`chimera_test_app` are non-root, database-scoped, and lack prohibited administrative privileges. The readiness probe checks connectivity, non-root identity, and the 11 expected tables without exposing the server, username, password, or SQL errors.

Backups, restore tests, retention, and schema imports remain explicit operator actions. Never use `chimera` for destructive integration tests; those require the exact isolated `chimera_test` name and dedicated account.
