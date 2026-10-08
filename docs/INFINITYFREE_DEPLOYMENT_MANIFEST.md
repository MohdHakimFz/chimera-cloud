# InfinityFree Deployment Manifest

This manifest is locally validated. Gate A passed and the operator has authorized Gate B's non-secret upload only. Do not create `.env`, import the database, or proceed beyond Gate B without the corresponding later gate.

## UPLOAD to `/htdocs`

| Local source | Production destination | Notes |
|---|---|---|
| `.htaccess` | `/htdocs/.htaccess` | Use the reviewed InfinityFree root deny/rewrite policy; first back up and merge required provider directives. |
| `app/` | `/htdocs/app/` | Required source; direct HTTP access must be denied. |
| `bootstrap/` | `/htdocs/bootstrap/` | Required bootstrap; direct HTTP access must be denied. |
| `config/` | `/htdocs/config/` | Placeholder-driven PHP configuration; direct HTTP access must be denied. |
| `public/index.php` | `/htdocs/public/index.php` | Existing front controller; no PHP path change needed with this tree. |
| `public/.htaccess` | `/htdocs/public/.htaccess` | Defense-in-depth routing/secret-file policy. |
| `public/assets/` | `/htdocs/public/assets/` | Public static files, exposed canonically through `/assets/*`. |
| `resources/` | `/htdocs/resources/` | Views; direct HTTP access must be denied. |
| `routes/` | `/htdocs/routes/` | Route declarations; direct HTTP access must be denied. |
| `storage/.htaccess` | `/htdocs/storage/.htaccess` | Denies the complete storage tree. |
| `storage/uploads/.htaccess` | `/htdocs/storage/uploads/.htaccess` | Additional executable-file denial. |
| empty runtime directory markers | matching `/htdocs/storage/...` directories | Upload no local log, session, document, quarantine, or E2E content. |

Only the following writable runtime paths are expected:

```text
/htdocs/storage/logs/
/htdocs/storage/sessions/
/htdocs/storage/uploads/documents/
/htdocs/storage/uploads/documents/.trash/
```

Do not use mode 0777. Use the least permissions supported by the account ownership model and verify writes through low-impact application behavior.

## DO NOT UPLOAD

- Local `.env` or any file containing credentials/secrets.
- `database/` (schema/reference SQL is imported through the database administration channel, not served from `/htdocs`).
- `tests/`, `scripts/`, `docs/`, or `evidence/`.
- `.git/`, `.github/`, `.agents/`, `.codex/`, editor settings, caches, or local tooling metadata.
- `README.md`, `TODO.md`, `implementation.md`, `proceed.md`, reports, screenshots, or academic drafts.
- Local `storage/logs/*`, `storage/sessions/*`, `storage/uploads/*`, `.trash`, E2E files, or fixture artifacts.
- `.env.example`, test database configuration, local database dumps, `schema.sql`, development `seed.sql`, or seed synchronization scripts.
- Development users/documents/activity, telemetry, security sessions, contributors, honeytoken events, or vulnerability history.
- Backup/temp files including `.bak`, `.backup`, `.old`, `.orig`, `.save`, `.sql`, `.log`, `.ini`, `.dist`, or editor swap files.
- Composer/vendor content unless a future source audit introduces and verifies an actual runtime dependency. CHIMERA currently uses its own autoloader and has no required vendor tree.

## OPERATOR CONFIGURES MANUALLY

1. Confirm the exact `/htdocs` root and back up provider placeholder/configuration files.
2. Confirm PHP 8.2+ and all source-required extensions.
3. Use provider-confirmed MySQL port 3306; never reuse local port 3308.
4. Temporarily upload `deployment/infinityfree-env-denial-probe.txt` as `/htdocs/.env`, require 403/404 with no canary disclosure, delete it, and only then create the real `.env` manually.
5. Enter the database password and telemetry secret privately; never place them in the upload package or evidence.
6. Set absolute session/document storage paths using the provider's observed filesystem path.
7. Set least writable permissions for runtime storage only.
8. Import the schema once into the verified empty production database.
9. Import the reviewed production-reference seed; never import development `seed.sql`.
10. Provision one initial Security Admin without a default/known password.
11. Confirm `VULNERABILITY_LAB_ENABLED=false` before first request.
12. Remove confirmed `/htdocs/index2.html` and other exact provider placeholder files only at deployment time; do not touch hosting-root controls.
13. Run the NORMAL_SAFE low-impact validation and stop at the review checkpoint.

## Database manifest

### Import

- Eleven-table schema from `database/schema.sql`, once, only after confirming the target database is empty.
- A separately reviewed production-reference seed containing 3 decoys, 2 synthetic honeytokens, and 3 REMEDIATED module definitions.
- One operator-provisioned Security Admin account with a unique final password.

### Never import

- The three accounts or activity rows in development `database/seed.sql`.
- Any local/test user, document, activity, event, session, contributor, honeytoken event, state-change, or E2E record.
- `chimera` or `chimera_test` dumps.

## Deployment gate

Before the separately authorized upload, confirm:

- the implemented actual-web-root/storage readiness behavior remains unchanged;
- the reviewed production-reference seed remains the intended initialization artifact;
- provider MySQL port 3306, PHP 8.4.25, and all source-required extensions are verified;
- `.htaccess` support/required directives have a safe validation plan;
- all 563 checks pass with zero failures/skips;
- PHP lint passes for every PHP file;
- the operator explicitly approved Gate B's non-secret upload; this does not authorize secrets, database initialization, or application boot validation.
