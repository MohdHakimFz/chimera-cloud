# Phase 10 Deployment Validation Record

## Current checkpoint

Previous checkpoint: **PHASE 10 = BLOCKED ON DEPLOYMENT ACCESS** because the hosting account could not be provisioned.

Current checkpoint: **GATE A = PASS; GATE B NORMAL_SAFE NON-SECRET UPLOAD AUTHORIZED**. The operator verified PHP 8.4.25, all seven required PHP capabilities, writable runtime directories, the required Apache feature subset, and provider-confirmed MySQL port 3306. The temporary capability-check directory was removed and its URL returned 404. The complete production root policy, application files, HTTPS behavior, and production database remain undeployed/unvalidated. No production secret, database import/connection, live application request, lab activation, scan, or Kali activity has occurred.

Local compatibility implementation is complete, but upload approval remains a separate gate. The first deployed mode must be `NORMAL_SAFE` with production mode, debug disabled, HTTPS canonical URL, secure cookies, and `VULNERABILITY_LAB_ENABLED=false`. Protected-in-webroot readiness remains blocked until live denial verification is recorded.

## Capability status

| Capability | Status | Required evidence |
|---|---|---|
| Exact authorized CHIMERA origin | VERIFIED | Operator confirmed `https://projectchimera.infinityfreeapp.com`; live response remains untested. |
| PHP version and handler | VERIFIED | Temporary minimal checker reported PHP 8.4.25. |
| Required extensions | VERIFIED | PDO, pdo_mysql, mbstring, fileinfo, JSON, session, and hash all reported available. |
| Hosted database identity | VERIFIED | Operator confirmed a new empty InfinityFree database; password remains operator-only. |
| Hosted database port/connectivity | WARNING | InfinityFree vPanel explicitly reports port 3306; application connectivity remains unverified until the later secret/configuration gate. |
| Website document root | VERIFIED | InfinityFree File Manager identifies `/htdocs`; files must not be placed in the hosting root. |
| `.htaccess` and rewrite support | WARNING | Gate A verified RewriteEngine, RewriteRule, RewriteCond, FilesMatch, `Require all denied`, and `Options -Indexes` with no HTTP 500. The complete production root policy still requires Gate B verification. |
| HTTPS certificate and redirects | BLOCKED | Live certificate and redirect observations. |
| Direct PHP HTTPS indication | BLOCKED | Server-side preflight on the deployed request. |
| Protected-in-webroot writable storage | WARNING | Gate A verified writes to temporary logs, sessions, and uploads directories. Final `/htdocs/storage` paths and HTTP denial remain pending. |
| Private log access and retention | BLOCKED | Hosting panel/path policy confirmation. |
| PHP upload/runtime limits | BLOCKED | Host PHP configuration evidence. |
| Infrastructure rate limiting | HOSTING-DEPENDENT | Provider/control-panel documentation or observed configuration. |
| CDN/static cache behavior | HOSTING-DEPENDENT | Only applicable if the operator enables a CDN. |

Run `php scripts/phase10-hosting-preflight.php` through an authorized private CLI after files and private environment configuration are in place. The command is read-only, reports only classifications/non-secret limits, and returns non-zero for a blocked capability or failed production-readiness gate.

## Gate A evidence record

- Origin: `https://projectchimera.infinityfreeapp.com`
- Result: **PASS**
- PHP: 8.4.25
- Extensions/capabilities: PDO, pdo_mysql, mbstring, fileinfo, JSON, session, and hash all available
- Temporary runtime writes: logs, sessions, and uploads all successful
- Apache: direct PHP, RewriteRule, RewriteCond, FilesMatch denial, dotfile denial, private-directory denial, and directory-listing denial succeeded; no redirect loop or HTTP 500 was observed
- Database port: 3306, explicitly displayed by InfinityFree vPanel as `MySQL Port (optional)`
- Cleanup: `/htdocs/chimera-gate-a/` removed; the former checker URL returned 404
- Sensitive evidence: no password, cookie, session identifier, request header, filesystem path, or configuration value was collected

Gate A did not test the complete CHIMERA root `.htaccess`, HTTPS transport behavior, production database connectivity, or application boot. Those remain later gated checks.

## Ordered validation methodology

1. **Stage A — Capability discovery:** confirm the table above without guessing values. Stop for any missing required extension or unsafe root/storage constraint.
2. **Stage B — NORMAL_SAFE:** verify the production database is empty, import `database/schema.sql` once and the separately reviewed production-reference seed, create a unique denied `.env`, deploy the protected `/htdocs` layout, and keep the lab false. Never import development `database/seed.sql`.
3. **Stage C — Live validation:** verify HTTPS, sensitive-path denial, headers, errors, authentication, role separation, CSRF, owner-scoped documents, inert upload fixtures, telemetry, scoring, deception, adaptive behavior, analytics, and the Security Admin readiness gate.
4. **Checkpoint:** all critical NORMAL_SAFE checks must pass before lab consideration. A critical failure blocks further work.
5. **Stage D — Authorized lab:** requires separate explicit authorization confirming ownership, exact target, synthetic-only testing, and shared-hosting boundaries. The environment switch is the only lab enablement mechanism.
6. **Stage E — Handoff:** validate the three existing modules, vulnerable/remediated evidence, rollback, and scope plan. Do not execute the Kali plan without another explicit authorization.

## Production data rules

- Never copy the local `.env`, `chimera`, or `chimera_test` database to production.
- Initialize the verified 11-table schema from approved SQL only.
- Use synthetic seed/registry data and exclude local telemetry, sessions, contributors, documents, E2E accounts, and test events.
- Use the InfinityFree-provided database identity. If the provider does not permit a distinct lower-privilege runtime identity, record the exact observed privilege model as a hosting-dependent limitation; do not broaden it.
- Never record credentials in evidence.

## Live check record template

Each result must include timestamp, exact origin, mode, observation, status (`VERIFIED`, `WARNING`, `BLOCKED`, or `NOT APPLICABLE`), and a sanitized evidence reference. Required areas are HTTPS; headers; sensitive paths; DB/schema/account; storage; authentication; RBAC; CSRF; ownership; uploads; telemetry; scoring; static/adaptive deception; analytics; lab-off; and error disclosure.

Do not mark an unperformed check as verified. Browser/API checks must record the observed HTTP status and safe result without cookies, authorization headers, tokens, passwords, database details, or filesystem paths.

## Lab activation and rollback gate

Before lab activation, record the operator's separate explicit authorization and confirm a known-good application package, database backup, and ability to set `VULNERABILITY_LAB_ENABLED=false`. If unexpected behavior occurs, disable the lab, restrict target access if needed, restore known-good files/database through the hosting control plane, and rerun NORMAL_SAFE checks.

After academic activity, set the lab false and verify `/lab/sqli`, `/lab/idor`, and `/lab/xss` each return a safe 404. Preserve sanitized academic evidence unless the operator's retention policy requires removal.

## Evidence plan

Store only sanitized observations under `evidence/phase10/`. Suggested classifications are deployment, headers, authentication, RBAC, CSRF, ownership, uploads, telemetry, scoring, deception, adaptive, analytics, lab, and remediation. Do not store secrets, session identifiers, cookies, authorization headers, private keys, raw environment files, or database exports containing credentials.
