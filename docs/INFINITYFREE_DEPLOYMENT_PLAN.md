# InfinityFree Deployment Plan

## Checkpoint and scope

Status: **GATE A = PASS; READY FOR GATE B NORMAL_SAFE NON-SECRET UPLOAD**. No CHIMERA application upload, production secret, database import, or application live validation has occurred.

The verified account is active and the intended origin is `https://projectchimera.infinityfreeapp.com`. InfinityFree exposes `/htdocs` as the website document root and instructs the operator not to upload application files to the hosting-account root. No upload, production database connection/import, DNS change, HTTP request, lab activation, or pentest was performed while preparing this document.

Initial deployment is strictly `NORMAL_SAFE`: production environment, debug disabled, canonical HTTPS origin, and `VULNERABILITY_LAB_ENABLED=false`.

## Repository compatibility assessment

The repository normally expects this relationship:

```text
project root/
  bootstrap/app.php       defines BASE_PATH as project root
  public/index.php        requires ../bootstrap/app.php
  public/assets/
```

That relationship can be preserved inside `/htdocs`; therefore no PHP path change is required merely to boot the application. A root `.htaccess` can internally send application requests to `public/index.php` and map `/assets/*` to `public/assets/*`.

There is, however, one security-model incompatibility requiring review before upload: `DocumentStorage` and `ProductionSecurityValidator` treat `BASE_PATH/public` as the web root. On InfinityFree the actual web root is the wider `/htdocs`, so `/htdocs/storage` and `/htdocs/.env` are web-root-resident even though the current validator describes them as outside the public root. They can be protected with explicit Apache denial, but the existing readiness result would not accurately express that different trust boundary.

The approved narrow compatibility implementation now:

1. Uses `DEPLOYMENT_STORAGE_MODE=PROTECTED_IN_WEBROOT` so storage checks recognize the actual `/htdocs` boundary.
2. Requires the exact `storage/uploads/documents` runtime path plus all static deny controls.
3. Keeps readiness `BLOCKED` with `PENDING LIVE VERIFICATION` until `WEBROOT_DENIAL_VERIFIED=true` is set after real 403/404 checks.
4. Preserves upload path, filename, ownership, checksum, and execution controls.
5. Provides `database/production_reference_seed.sql` containing registry rows only; the 11-table schema remains unchanged.

The compatibility work passed local regression. Upload still requires a separate explicit operator authorization, and readiness cannot pass in protected mode until the live denial checks have actually been completed.

## Proposed `/htdocs` tree

```text
/htdocs/
  .htaccess                         InfinityFree-compatible root deny/rewrite policy
  .env                              manually created; never in upload package
  app/                              PHP application source; HTTP denied
  bootstrap/                        bootstrap/autoload; HTTP denied
  config/                           configuration source; HTTP denied
  public/
    .htaccess                       existing front-controller safeguards
    index.php                       existing front controller
    assets/
      css/app.css
      js/app.js
      images/hero-secure-documents.webp
  resources/                        views; HTTP denied
  routes/                           route declarations; HTTP denied
  storage/                          HTTP denied; writable only where required
    .htaccess
    logs/
      .gitkeep
    sessions/
      .gitkeep
    uploads/
      .htaccess
      .gitkeep
      documents/                    created/writable at deployment
        .trash/                     created/writable at deployment
```

Do not upload `database`, `docs`, `tests`, `scripts`, `evidence`, local `.env`, development logs/uploads/sessions, SQL dumps, or project notes into `/htdocs`.

The URL `/assets/...` is internally rewritten to `public/assets/...`; all other non-file/non-directory requests are internally rewritten to `public/index.php`. `APP_BASE_PATH` remains empty because the application is served at the origin root.

## Proposed `/htdocs/.htaccess`

The following is the required policy design, pending provider compatibility verification. Back up the provider-created `/htdocs/.htaccess` and merge any mandatory provider directives rather than overwriting them blindly.

```apache
Options -Indexes
ServerSignature Off

<IfModule mod_rewrite.c>
    RewriteEngine On

    # Private application trees. This rule must precede file/directory bypasses.
    RewriteRule ^(?:app|bootstrap|config|database|docs|evidence|resources|routes|scripts|storage|tests|vendor)(?:/|$) - [F,L,NC]

    # Repository/development artifacts that must never be served.
    RewriteRule ^(?:README\.md|TODO\.md|implementation\.md|proceed\.md|composer\.(?:json|lock)|phpunit\.xml(?:\.dist)?)$ - [F,L,NC]

    # Preserve the public URL while retaining public/ as the code-level front-controller directory.
    RewriteRule ^assets/(.*)$ public/assets/$1 [L,NC]

    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^ public/index.php [QSA,L]
</IfModule>

<FilesMatch "(?i)^(?:\.|.*\.(?:env|ini|log|sql|bak|backup|old|orig|save|dist))$">
    Require all denied
</FilesMatch>
```

Deployment must stop if `mod_rewrite`, `Options -Indexes`, or `Require all denied` causes a provider error or is ignored. Do not remove a failed control without designing and validating a safe provider-compatible replacement. Existing `storage/.htaccess` and `storage/uploads/.htaccess` remain defense in depth.

Direct `/public/...` URLs are not the canonical surface. They expose only the front controller/static assets, not private source; canonical application links remain rooted at the configured `APP_URL`. Whether a safe canonical redirect should be added is a later live-observation decision, not required for boot compatibility.

## Existing path and configuration behavior

- `public/index.php` resolves the bootstrap with `dirname(__DIR__)`; this remains correct at `/htdocs/public/index.php`.
- `bootstrap/app.php` sets `BASE_PATH=/htdocs`, loads `/htdocs/.env`, loads source/views/routes from that base, and logs to `/htdocs/storage/logs/application.log`.
- Default sessions use `/htdocs/storage/sessions`.
- Default documents use `/htdocs/storage/uploads/documents`; quarantine uses its `.trash` child.
- `asset()` emits `<APP_URL>/assets/...`, requiring the root asset rewrite above.
- `Request` requires an empty `APP_BASE_PATH` for an origin-root deployment.
- The PDO DSN always includes `DB_PORT`. InfinityFree vPanel explicitly identifies the production MySQL port as `3306`; local port `3308` remains local-only.
- HTTPS detection trusts only direct `HTTPS`/`REQUEST_SCHEME`; InfinityFree behavior remains live-validation pending.

## Environment template (placeholders only)

The operator manually creates `/htdocs/.env` only after access denial is proven with a non-secret canary. Never upload the local `.env`.

Required sequence:

1. Upload the non-secret application/access-control structure without a real `.env`.
2. Temporarily upload `deployment/infinityfree-env-denial-probe.txt` as `/htdocs/.env`.
3. Request `/.env`; require 403 or 404 and verify the response body does not contain `CHIMERA_ENV_DENIAL_PROBE_ONLY`.
4. Delete the probe immediately.
5. Only then create the real `/htdocs/.env` manually with operator-held secrets.

A 404 for a nonexistent file alone is not sufficient proof; the temporary canary makes the denial check meaningful.

```dotenv
APP_NAME="CHIMERA CLOUD"
APP_ENV=production
APP_DEBUG=false
APP_URL=https://<AUTHORIZED_CHIMERA_HOST>
APP_BASE_PATH=
APP_TIMEZONE=<PRODUCTION_TIMEZONE>
HTTPS_ENFORCE=<true-after-direct-https-validation>

DB_HOST=<INFINITYFREE_DB_HOST>
DB_PORT=3306
DB_DATABASE=<INFINITYFREE_DB_NAME>
DB_USERNAME=<INFINITYFREE_DB_USERNAME>
DB_PASSWORD=<OPERATOR_ENTERS_SECRET_MANUALLY>
DB_CHARSET=utf8mb4

SESSION_NAME=<UNIQUE_PRODUCTION_SESSION_NAME>
SESSION_SECURE=true
SESSION_SAMESITE=Lax
SESSION_LIFETIME=7200
SESSION_SAVE_PATH=<ABSOLUTE_HTDOCS_STORAGE_SESSIONS_PATH>

DOCUMENT_STORAGE_PATH=<ABSOLUTE_HTDOCS_PRIVATE_STORAGE_PATH>
DOCUMENT_MAX_BYTES=<VALUE_WITHIN_PROVIDER_POST_AND_UPLOAD_LIMITS>
DOCUMENT_ALLOWED_EXTENSIONS=pdf,txt,csv,md

TELEMETRY_HASH_KEY=<OPERATOR_GENERATES_UNIQUE_RANDOM_VALUE_AT_LEAST_32_CHARACTERS>
VULNERABILITY_LAB_ENABLED=false
```

Do not configure test-database variables in production. The password and telemetry secret are entered through the operator's secure process and are never recorded in deployment evidence.

## Production-safe database import

`database/schema.sql` defines the required 11 tables but begins with `DROP TABLE IF EXISTS`. It may be imported once only after the operator verifies that the new production database is empty and correctly selected. Never rerun it against a database containing production evidence or accounts.

Do **not** import `database/seed.sql`: it contains three known synthetic development accounts, their activity rows, and known password hashes. Do not execute `sync_phase4_seed.php` or `sync_phase7_seed.php`; both deliberately refuse any database other than local `chimera` on port 3308.

After approval, create and review a production-reference seed containing only:

- the three static decoy registry rows;
- the two CHIMERA synthetic honeytoken registry hashes;
- the three vulnerability-module registry definitions, initially `REMEDIATED`, while the global lab remains disabled;
- no users, activity, documents, telemetry, sessions, contributors, honeytoken events, or state history.

Import order:

1. Confirm the selected production database is empty.
2. Import `schema.sql` once through the authorized InfinityFree database tool and confirm exactly 11 tables.
3. Import the reviewed production-reference seed.
4. Confirm operational/event tables remain empty and only eight registry rows exist (3 decoys, 2 honeytokens, 3 modules).
5. Provision the initial Security Admin separately.

## Initial Security Admin provisioning

Never ship a default account or known password. Preferred process:

1. After HTTPS and database connectivity are validated, register a unique synthetic operator account through the normal CSRF-protected registration flow using a strong final password from the operator's password manager.
2. In the authorized database administration interface, verify the exact email and update only that account's role from `user` to `security_admin`.
3. Sign out, sign in again, verify the new session receives only Security Admin capabilities, and confirm `/admin` remains denied.
4. Record no plaintext password, hash, session value, or authentication header in evidence.

If registration is intentionally disabled later, an alternative is an operator-generated PHP `password_hash()` value inserted through the database administration interface. Only the hash—not a default plaintext password—may enter SQL. This alternative requires a separately reviewed one-time procedure.

## Provider placeholder files

- `/htdocs/index2.html` may be removed at the actual deployment step after its provider-placeholder content is confirmed and the file is backed up if desired.
- Any other instruction/placeholder file inside `/htdocs` may be removed only after its exact filename and provider purpose are confirmed. Do not use wildcard deletion.
- Do not modify hosting-root `/.htaccess`, `/.override`, or `DO NOT UPLOAD FILES HERE`; they are outside `/htdocs` and may be provider controls.

## NORMAL_SAFE post-deployment validation

Use only low-impact browser/curl checks after explicit upload approval:

1. Verify certificate, canonical origin, HTTP-to-HTTPS behavior, and PHP's direct HTTPS indicator without trusting arbitrary forwarded headers.
2. Verify `/`, assets, login, and registration render without debug/path/database disclosure.
3. Verify `.env`, private directories, SQL/log/backup filenames, repository artifacts, and directory listings return 403/404.
4. Verify required PHP extensions and provider limits with the application-specific preflight; do not publish `phpinfo()`.
5. Verify database connectivity, exactly 11 tables, expected reference counts, and no development/test records.
6. Verify writable sessions/logs/uploads while source/configuration remain non-writable where hosting permissions permit.
7. Verify security headers, no-store policy, Secure/HttpOnly/SameSite cookies, session regeneration, and logout invalidation.
8. Verify USER/ADMIN/SECURITY ADMIN separation, CSRF, owner-scoped documents, safe uploads/downloads, telemetry, scoring, deception, adaptive behavior, and analytics.
9. Verify `/lab/sqli`, `/lab/idor`, and `/lab/xss` return safe 404 and the private readiness view reports lab disabled.
10. Stop for review. Do not enable the lab and do not run automated scanning.

## Hosting capability verification

| Capability | Source classification | Hosting classification |
|---|---|---|
| PHP 8.2+ | SOURCE REQUIRED | VERIFIED: PHP 8.4.25 |
| PDO | SOURCE REQUIRED | VERIFIED |
| pdo_mysql | SOURCE REQUIRED | VERIFIED |
| mbstring | SOURCE REQUIRED | VERIFIED |
| fileinfo | SOURCE REQUIRED | VERIFIED |
| JSON | SOURCE REQUIRED | VERIFIED |
| session | SOURCE REQUIRED | VERIFIED |
| hash | SOURCE REQUIRED | VERIFIED |

Verified at Gate A: MySQL port 3306; RewriteEngine, RewriteRule, RewriteCond, FilesMatch, `Require all denied`, `Options -Indexes`; and temporary logs/sessions/uploads writes. Still pending: database service/version and connectivity, the complete production root policy, PHP upload/runtime limits, final runtime-path permissions, log access/retention, certificate/redirect behavior, direct HTTPS indication, Secure-cookie behavior, and actual application response headers.
