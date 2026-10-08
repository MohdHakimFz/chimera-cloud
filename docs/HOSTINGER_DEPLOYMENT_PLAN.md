# Hostinger Deployment Plan

> Historical platform plan: this file records the earlier Hostinger-oriented assumptions and remains useful as general shared-hosting guidance. The active Phase 10 target is now InfinityFree. Use `INFINITYFREE_DEPLOYMENT_PLAN.md` and `INFINITYFREE_DEPLOYMENT_MANIFEST.md`; do not apply the private-root/public_html assumptions below to the verified `/htdocs` environment.

No Hostinger deployment occurred.

## Ordered Phase 10 stages

- **Stage A — capability discovery:** run the private CLI preflight, confirm the target and hosting panel values, and classify every unknown. Do not guess.
- **Stage B — NORMAL_SAFE deployment:** deploy with production/debug false and lab false using the private/public layout below.
- **Stage C — live security validation:** verify the deployed application and Security Admin readiness result. Any critical failure stops the process.
- **Stage D — authorized lab activation:** proceed only after a separate operator authorization for the exact owned/controlled target.
- **Stage E — pentest-readiness handoff:** validate controlled modules and rollback, then stop before Kali execution.

## Platform requirements

- PHP 8.2+ with PDO, pdo_mysql, mbstring, fileinfo, JSON, session, and hash. These are the extensions actually used by application source. TLS support is a hosting/web-server requirement; the application does not directly call OpenSSL.
- MariaDB/MySQL-compatible InnoDB and utf8mb4 behavior; verify the actual Hostinger database version in Phase 10.
- Apache-compatible rewrites and access-control directives. Module availability is HOSTING-DEPENDENT.
- No root, Docker, systemd, Redis, workers, custom firewall, or daemon is assumed.

## Preferred layout

Point the domain document root directly to `public/`. Keep `app`, `bootstrap`, `config`, `database`, `docs`, `scripts`, `storage`, `tests`, and `.env` one level above the public directory. Only `index.php`, `.htaccess`, and static assets belong in the public root.

If Hostinger cannot change the document root, place private application files outside `public_html`, copy only the contents of `public/` into `public_html`, and adjust the bootstrap path in the public front controller. Do not place `.env`, storage, SQL, tests, or docs inside `public_html`. Exact path/ownership controls are HOSTING-DEPENDENT.

## Configuration and database

Create the database/schema through the hosting control panel/import tool, then configure a database-scoped non-admin runtime account. Store actual credentials only in the private `.env`. Use `.env.example` as a checklist, never as a secret file.

Configure an absolute private document-storage path, plus writable private log/session/upload directories. Verify ownership and use least permissions rather than 0777.

## HTTPS, sessions, and Apache

Activate and verify the hosting certificate first. Confirm PHP receives a direct trustworthy HTTPS indicator. Then set the HTTPS application URL, enable enforcement, Secure cookies, and normal-mode lab false. If the host terminates TLS behind a proxy without direct indicators, do not trust forwarded headers globally; document a host-specific trusted boundary before any code change.

Validate `mod_rewrite`-equivalent behavior, `Require` access rules, disabled indexes, dotfile denial, protected storage/logs, and non-execution in writable directories. Static assets must continue to resolve.

## Verification modes

Normal mode must show readiness without critical failures and return 404 for every `/lab/*` route. Authorized lab mode may be enabled only for a specifically authorized academic target; verify the warning, synthetic module boundary, zero operational contribution, and unchanged real application security.

Run `php scripts/phase10-hosting-preflight.php` from an authorized private CLI when available. If Hostinger provides no CLI, capture the same capability evidence from the control panel and use the Security Admin `/security/deployment-readiness` page for the non-secret readiness result. Never expose either detailed mechanism publicly.

## Rollback concept

Retain the previous code package, private environment backup, and database backup. Roll back code atomically where the control panel permits, restore only a compatible database snapshot, revert lab mode to the intended state, rotate secrets if exposure is suspected, and rerun safe readiness/smoke checks.
