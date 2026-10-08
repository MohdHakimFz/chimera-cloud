# Deployment Checklist

For the active InfinityFree target, use this general checklist together with `INFINITYFREE_DEPLOYMENT_PLAN.md`. InfinityFree's verified `/htdocs` restriction means private application paths and the manually created `.env` require explicit, live-verified HTTP denial; the preferred outside-web-root layout is not currently available.

## Phase 10 authorization and access

- Confirm the exact owned/controlled CHIMERA HTTPS origin; leave all provider/shared infrastructure out of scope.
- Confirm a secure hosting-access channel without placing credentials in repository files, prompts, logs, or evidence.
- Run `php scripts/phase10-hosting-preflight.php` privately where CLI exists, or record equivalent hosting-panel evidence.
- Do not proceed beyond preparation while target/access remains unconfirmed.

## Pre-upload

- Run all Phase 1–10 local suites, PHP lint, secret scan, route scan, and `php scripts/check-deployment-readiness.php` with planned production configuration.
- Confirm normal versus explicitly authorized lab mode.
- Create an encrypted backup and rollback package.

## Database

- Confirm the selected production database is empty, then import initialization-only `schema.sql` once and `production_reference_seed.sql` separately.
- Use the least-privilege runtime identity supported by the provider; document a hosting limitation if InfinityFree cannot separate owner/runtime privileges.
- Verify 11 tables, utf8mb4, foreign keys, and no global/admin privileges.

## Environment

- Prefer `.env` outside the public document root. Under the verified InfinityFree constraint, temporarily place the supplied non-secret canary at `/htdocs/.env`, require 403/404 with no marker disclosure, delete it, and only then create the real `/htdocs/.env` manually. A missing-file 404 alone is not proof.
- Set production, debug false, HTTPS URL/enforcement, unique DB password, Secure session cookie, long telemetry hash key, absolute private storage path, and intended lab state.
- Never upload a local development `.env` or test credentials.

## Web root and Apache

- On InfinityFree retain `/htdocs/public/index.php`; use the reviewed root rewrite to serve it at the origin root and map allowlisted `/assets/*` paths.
- Confirm rewrite, authorization, and headers modules needed by `.htaccess`.
- Verify dotfiles, storage, logs, config, database, docs, tests, and scripts are unreachable.

## HTTPS and sessions

- Verify the certificate/redirect at the host before enabling `HTTPS_ENFORCE=true`.
- Confirm direct HTTPS server indicators, HSTS, Secure/HttpOnly/SameSite cookie flags, regeneration, and logout invalidation.

## Storage and permissions

- Keep uploads, quarantine, sessions, and logs outside application `public/`; in InfinityFree protected mode they stay under the explicitly denied `/htdocs/storage` tree.
- Grant only the PHP account/group required write access; never use 0777 by default.
- Verify PHP cannot execute in writable directories.

## Security headers and mode

- Verify CSP, nosniff, frame protection, referrer/permissions policy, cache policy, and conditional HSTS.
- Normal deployment: lab false and `/lab/*` returns 404.
- Authorized academic deployment: lab warning visible only to Security Admin and real application remains secure.

## Post-deployment verification

- Run non-destructive login/logout, RBAC, owner-document, API, error, header, private-storage, telemetry, analytics, and readiness smoke checks.
- Do not run destructive or external offensive testing without separate written authorization.

## NORMAL_SAFE checkpoint

- Verify `APP_ENV=production`, `APP_DEBUG=false`, and `VULNERABILITY_LAB_ENABLED=false` without printing values that are secrets.
- Confirm HTTPS, sensitive-path denial, private storage, database/schema/runtime identity, authentication, RBAC, CSRF, ownership, upload controls, telemetry, scoring, static/adaptive deception, analytics, and safe errors.
- Confirm `/lab/sqli`, `/lab/idor`, and `/lab/xss` return 404.
- Stop on any critical FAIL. Obtain separate explicit operator authorization before changing lab mode.

## Authorized lab checkpoint

- Record target ownership, exact origin, synthetic-only scope, shared-hosting boundary, rollback, and separate operator authorization.
- Enable only the environment lab switch; do not weaken any real-application control.
- Verify only the three registered modules, zero-score LAB telemetry, vulnerable/remediated comparison, and real-application isolation.
- Stop before executing the Kali plan; that requires another explicit authorization.

## Rollback

- Disable traffic or restore the prior public release atomically.
- Restore the matching database backup only through an approved administrative procedure.
- Preserve protected logs/evidence, rotate exposed secrets if suspected, and verify normal mode before reopening.
