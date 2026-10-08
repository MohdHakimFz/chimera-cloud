# CHIMERA CLOUD

CHIMERA CLOUD is an academic cybersecurity web application combining secure document management, security telemetry, threat assessment, adaptive deception, and a separately controlled vulnerability lab. It supports authorized security research and the NWC3293 Ethical Hacking and Penetration Testing assessment.

The live application and its isolated training clone are separate testing tracks. Production is hosted on InfinityFree shared hosting with the vulnerability lab disabled. Deliberately vulnerable SQLi, IDOR, and reflected-XSS exercises belong only in an isolated clone.

**Live application:** [CHIMERA CLOUD](https://projectchimera.infinityfreeapp.com/) · [Production login](https://projectchimera.infinityfreeapp.com/login). Use only an account you are authorized to access; the repository does not contain production credentials.

## What it includes

- Role-aware workspaces for USER, ADMIN, and SECURITY ADMIN.
- Owner-scoped documents with private storage and application-mediated downloads.
- Security-event telemetry, deterministic threat scoring, and SOC analytics.
- Bounded decoy and honeytoken research surfaces.
- A default-off, synthetic vulnerability lab for separately authorized isolated testing.
- Light and dark presentation with responsive navigation.

## Architecture

The application uses a small server-rendered MVC structure with a single public entry point:

```text
public/index.php -> bootstrap/app.php -> routes/web.php -> middleware -> controller -> model/view
```

- `app/Core`: request lifecycle, routing, sessions, PDO, responses, views
- `app/Controllers`: HTTP coordination only
- `app/Models`: prepared database access
- `app/Middleware`: authentication, role, guest, and CSRF guards
- `app/Security`: authentication, CSRF, and response headers
- `app/Services`: secure file-storage and document lifecycle operations
- `resources/views`: escaped server-rendered PHP templates
- `public`: front controller and public assets
- `database`: schema and synthetic seed data
- `storage`: private documents, logs, and sessions; denial policies are required when deployed within a webroot

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Requirements

- Install MariaDB 10.6+ (or MySQL 8.0+) and start its database service before setting up CHIMERA.
- PHP 8.1 or newer with PDO MySQL, mbstring, fileinfo, JSON, session, and hash support
- Apache with `mod_rewrite`, or the PHP development server for local use
- Git to clone the project; Node.js/npm only if you intend to rebuild frontend assets
- HTTPS for any remote deployment

The deployed UI uses local compiled CSS, JavaScript, and fonts; it does not depend on Tailwind's browser CDN. Node.js is needed only when rebuilding frontend assets. The PHP application itself does not require Composer.

## Installation

1. Install and start **MariaDB**, install PHP with the extensions above, and confirm both `mariadb` (or `mysql`) and `php` work in your terminal. XAMPP can provide PHP/Apache, but its bundled database is not automatically the separate MariaDB instance used by this project's verified Windows setup.
2. Clone this repository, then copy `.env.example` to a local `.env`; never commit that file.
3. Create a **new empty** `chimera` database and a database-scoped, least-privilege application user in MariaDB. Use your own unique password, not a credential from this repository.
4. Set `DB_HOST`, `DB_PORT`, `DB_DATABASE`, `DB_USERNAME`, and `DB_PASSWORD` in `.env` to match that MariaDB instance. Set `APP_URL=http://127.0.0.1:8000` for the local server. Keep `VULNERABILITY_LAB_ENABLED=false`.
5. Import `database/schema.sql` **only into that empty disposable database**: it drops and recreates its 11 named tables. `database/seed.sql` contains known synthetic development accounts and must never be used as a production seed.
6. Start the app with the command below and open the local URL in a browser. For Apache, point the local document root at `public/`. Keep private storage outside `public/`; use the documented protected-in-webroot layout only when hosting requires it.

The verified Windows development topology uses MariaDB at `127.0.0.1:3308`, database `chimera`, and a database-scoped `chimera_app` runtime account. A separate `chimera_test` database is reserved for integration tests. These local settings are not production credentials or a lab-clone configuration.

Example development command after configuring the local database:

```powershell
php -S 127.0.0.1:8000 -t public
```

Then visit `http://127.0.0.1:8000/login`. The `tests/e2e_server_router.php` file is **only for the isolated test harness** and must not be used as a normal development server. See [docs/DATABASE.md](docs/DATABASE.md) and [docs/TESTING.md](docs/TESTING.md) before initializing a database or running tests.

## Environment configuration

`APP_DEBUG` must be `false` remotely. Set `SESSION_SECURE=true` after HTTPS is active. If deployed below a subdirectory, set both `APP_URL` and `APP_BASE_PATH`, for example:

```dotenv
APP_URL=https://example.test/chimera
APP_BASE_PATH=/chimera
```

Never commit `.env` or real credentials.

Phase 2 file settings:

```dotenv
# Leave empty to use storage/uploads/documents outside public/
DOCUMENT_STORAGE_PATH=
DOCUMENT_MAX_BYTES=5242880
DOCUMENT_ALLOWED_EXTENSIONS=pdf,txt,csv,md
```

Any configured storage path must be absolute and outside `public/`. Existing paths and parent directories are canonicalized before the boundary check; downloaded document files may not be symbolic links.

## Accounts and roles

Public registration creates only a USER. ADMIN and SECURITY ADMIN privileges are assigned through controlled administration, never from registration input. Development seed accounts are synthetic and use known credentials; do not reuse them on a remotely reachable instance.

## Security architecture

Legitimate components use password hashing, native prepared statements, output escaping, secure session settings, CSRF checks for state changes, role guards, and conservative response headers. The application never logs plaintext passwords.

Admin can access `/admin` but not `/security`. Security Admin can access `/security` but not `/admin`. This is deliberate role separation, not a hierarchy.

## Profile and document ownership

Profile updates accept only the authenticated account's display name. Account ID, email, role, activation state, and security fields are not accepted from profile request input.

Every private document query is scoped by both `documents.id` and the authenticated `users.id`. Changing a browser-visible document ID cannot retrieve, download, or delete another account's document. Original filenames are metadata only and are never used as storage paths.

## Secure uploads and storage

Uploads are limited by configurable size and extension, validated using server-detected MIME, required to originate from PHP's HTTP-upload mechanism, renamed using 192 bits of randomness, checksummed, and stored outside the public root. Downloads pass through authentication and ownership checks, then verify size and SHA-256 integrity before streaming.

Deletion first moves an existing file into a non-public quarantine location. The ownership-scoped database deletion and activity record then commit together. A database failure restores the file. After a successful commit, quarantine cleanup is best effort. A missing file does not prevent removal of its stale database record, and that condition is captured only as legitimate activity metadata.

## Authorized API

The secure Phase 2 API uses the existing session:

- `GET /api/me`
- `GET /api/documents`
- `GET /api/documents/{id}`

Unauthenticated requests receive JSON `401`; inaccessible or nonexistent document resources receive the same JSON `404`. Responses omit storage names, internal paths, password data, session data, and document contents.

## User activity

`user_activity` stores legitimate product actions such as account creation, login, profile update, upload, download, and deletion. It stores no passwords, session identifiers, tokens, or document contents. This product-history model remains intentionally separate from `security_events` telemetry.

## Security telemetry

Phase 3 records security-relevant events through one fail-safe service into `security_events`. The service applies a fixed taxonomy and deterministic severity, uses the direct peer IP (`REMOTE_ADDR`) only transiently to derive a SHA-256 source identifier (HMAC when `TELEMETRY_HASH_KEY` is configured), and does not persist or present the raw address. It sanitizes explicit metadata and never captures complete request bodies, cookies, authorization headers, CSRF values, passwords, document contents, or internal storage paths.

Security Admin can use `/security`, `/security/events/{id}`, `/api/security/events`, `/api/security/events/{id}`, and `/api/security/summary`. User and Admin roles receive 403; unauthenticated API clients receive JSON 401. See [docs/SECURITY_TELEMETRY.md](docs/SECURITY_TELEMETRY.md).

## Deception and threat scoring

Phase 4 exposes the configured `/admin-old`, `/internal`, and `/api/debug` synthetic surfaces. Active routes return inert responses and record `DECOY_ACCESSED`. Registered, non-functional `CHM_HONEY_*` markers can be presented to `/api/debug/verify`; valid registry matches record `HONEYTOKEN_TRIGGERED` and return a fixed safe response. No blocking, external callback, or automatic activation occurs. See [docs/CYBER_DECEPTION.md](docs/CYBER_DECEPTION.md).

Phase 5 correlates events into 30-minute security sessions using safe source identifier plus exact actor boundary. Documented contributors update a score bounded to 0–100 and a descriptive LOW/MEDIUM/HIGH/CRITICAL assessment. Phase 6 maps that classification to minimal, contextual, investigative, or immersive-safe synthetic output. Assessment never participates in authentication, RBAC, document access, or legitimate APIs. See [docs/THREAT_SCORING.md](docs/THREAT_SCORING.md) and [docs/ADAPTIVE_DECEPTION.md](docs/ADAPTIVE_DECEPTION.md).

Security Admin adaptive views are available at `/security/adaptive`, with read-only APIs at `/api/security/adaptive/summary`, `/api/security/adaptive/events`, and `/api/security/sessions/{id}/deception`.

## Vulnerability lab and remediation

The controlled lab is disabled by default through `VULNERABILITY_LAB_ENABLED=false`. When an operator explicitly enables it, `/lab/sqli`, `/lab/idor`, and `/lab/xss` demonstrate bounded SQL injection, synthetic object authorization, and sandboxed reflected XSS. Security Admin can observe status and switch individual modules between `VULNERABLE` and `REMEDIATED`, but cannot enable the environment switch through HTTP. See [docs/VULNERABILITY_LAB.md](docs/VULNERABILITY_LAB.md).

## Security analytics and evidence

Phase 8 exposes `/security/analytics` and Security Admin-only `/api/security/analytics/*` reads. It measures events, operational sessions, stored score progression, detection latency, time to genuine decoy interaction, time to honeytoken interaction, adaptive-profile observations, and a separate controlled-LAB vulnerable/remediated comparison. JSON and CSV exports are bounded and minimized; CSV cells with formula-capable prefixes are neutralized. Analytics never changes evidence, scores, profiles, module state, or application behavior.

## Testing

Run the canonical local regression with:

```powershell
php tests/run.php
php scripts/scan-secrets.php
Get-ChildItem -Recurse -Filter *.php | ForEach-Object { php -l $_.FullName }
```

The integration and HTTP/E2E suites require the isolated `chimera_test` database and its dedicated account. They refuse unsafe database targets. The last accepted full baseline was 40 suites, 1030 passed, 0 failed, and one justified environment-dependent skip; PHP lint passed 161/161 files. A later focused local LAB-navigation test added two assertions, but a new full canonical count has not yet been established. See [docs/TESTING.md](docs/TESTING.md).

## Deployment and research boundaries

Security Admin can inspect `/security/deployment-readiness`. Production uses an InfinityFree-compatible `/htdocs` layout with private-path denial and `PROTECTED_IN_WEBROOT` storage mode. The production vulnerability lab stays globally disabled. See [docs/INFINITYFREE_DEPLOYMENT_MANIFEST.md](docs/INFINITYFREE_DEPLOYMENT_MANIFEST.md), [docs/PRE_PENTEST_TARGET_FREEZE.md](docs/PRE_PENTEST_TARGET_FREEZE.md), and [docs/PENTEST_SCOPE_AND_ROE.md](docs/PENTEST_SCOPE_AND_ROE.md).

The production target was frozen after Gate H and post-deployment validation. Track A reconnaissance and bounded scanning have been completed; no confirmed vulnerability was identified within those limited tests. Track B requires a separately approved isolated clone. Do not interpret the completed observations as proof that the whole application is vulnerability-free. This repository includes a later local-only LAB navigation improvement and must not be assumed byte-identical to the frozen production deployment.

## Ethical-use warning

Use CHIMERA only in systems you own or have explicit permission to test. Do not connect synthetic honeytokens to real services, add remote shells, collect real credentials, attack visitors, or extend lab weaknesses beyond the application boundary.

## Repository hygiene

The local `.env`, private uploads, sessions, logs, deployment archives, screenshots, and pentest evidence are excluded from Git. Before publishing any future evidence or screenshots, review and redact them separately. No GitHub push deploys or changes the InfinityFree production instance.
