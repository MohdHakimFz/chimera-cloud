# Security Model

## Trust boundaries

### Normal secure application

Authentication, profiles, documents, activity, administration, and normal APIs are production-like. They must use prepared statements, output escaping, CSRF protection for state changes, ownership checks, strict sessions, and explicit authorization.

### Vulnerability lab

Intentional behavior is restricted to the default-off `/lab` namespace, three allowlisted module IDs, synthetic records, and Security Admin controlled comparison states. The SQLi query can address only fixed inline literals; IDOR accepts only `LAB-*` objects; reflected XSS runs without same-origin or network capability. Lab services cannot call shell commands, access arbitrary files, change infrastructure, expose environment values, or share unsafe helpers with normal routes.

### Deception

Decoy endpoints and honeytokens are configuration-backed, static, and inert. Responses may look plausible but contain no usable credentials, external access, executable payloads, or visitor-side retaliation. Interactions emit centralized telemetry but never affect authentication, authorization, documents, permissions, or future responses.

### Monitoring

Telemetry accepts normalized facts from other components. It stores safe identifiers, summaries, and structured metadata, never passwords, cookies, raw session IDs, real tokens, or document contents. Dashboard reads are restricted to Security Admin.

Phase 3 implements this boundary through a centralized fail-safe service. Only `REMOTE_ADDR` is accepted as the transient direct-peer input for HMAC source correlation; it is not persisted in event metadata or exposed in telemetry presentation. Proxy forwarding headers are ignored until a trusted-proxy policy exists. Event metadata is explicit, bounded, key-filtered, and never built from a full request body or arbitrary headers.

## Phase 1 controls

- `password_hash()` and `password_verify()` with PHP's current default
- Session ID regeneration at authentication
- Strict, cookie-only, HttpOnly sessions with configurable Secure and SameSite flags
- CSRF token validation on login, registration, and logout
- Native PDO prepared statements with emulation disabled
- Context-safe HTML escaping by default in templates
- Exact role checks for Admin and Security Admin
- CSP, frame, MIME-sniffing, referrer, and permissions headers
- Generic production errors with server-side logging

## Phase 2 controls

- Profile updates allowlist only `name`; account and role identifiers never come from request assignment
- Document reads and mutations use `WHERE id = :id AND user_id = :user_id`
- Upload size, allowlisted extension, detected MIME, and `is_uploaded_file()` validation
- Original names reduced to safe metadata; random internal filenames provide no attacker-controlled path segments
- Canonical absolute non-public storage requirement, symlink rejection, and direct-access denial as defense in depth
- Size and SHA-256 verification before download
- Attachment-only controlled download with encoded Content-Disposition and no internal path disclosure
- POST plus CSRF for upload, profile update, and deletion
- Quarantine/transaction/rollback deletion strategy
- JSON-aware 401, 404, and 500 responses without stack traces
- Private owner-scoped activity and exact Admin/Security Admin separation

## Phase 2 security review

The review covered SQL injection, stored/reflected XSS, CSRF, IDOR/BOLA, traversal, file upload, arbitrary file access, authorization, mass assignment, information disclosure, direct filesystem exposure, and role escalation. Database values are bound, view values are escaped, JSON is encoded, file paths derive only from constrained random storage names, and all document access is owner-scoped.

Phase 3 provides passive event generation. Phase 4 adds deterministic decoy routing and synthetic honeytoken triggering only. Neither layer independently changes authorization or responses based on observed behavior.
At the Phase 5 boundary, descriptive threat assessment correlates by pseudonymous source and actor boundary, never by raw cookie or PHP session ID. Scores cannot block requests, change roles, activate decoys, modify documents, suspend accounts, or alter legitimate responses.

Phase 6 permits the stored assessment to select only the content richness of an already configured synthetic decoy. LOW/MEDIUM/HIGH/CRITICAL profiles never change route activation, legitimate responses, access-control results, or real data. Missing assessment and internal failures fall back to LOW. Profile telemetry scores zero, and repeat renders of the same decoy do not repeatedly increase assessment.

Phase 7 lab events use category `LAB`, receive zero score, and are not attached to operational security sessions. Enabling the lab is environment-only. Security Admin state changes are exact-role, POST-only, CSRF-protected, allowlisted, transactional, and audited; they cannot affect the global switch or non-lab routes.

## Phase 2.5 verified boundaries

Database-backed HTTP tests confirmed bidirectional owner isolation for document lists, details, downloads, deletion, and API resources; foreign resources return the same 404 as missing resources. Exact-role tests confirmed User, Admin, and Security Admin do not inherit one another's privileged dashboards. Upload tests covered extension, detected MIME, size, malformed requests, duplicate names, and traversal-style original names. Download tests covered authorization, safe disposition, path non-disclosure, missing IDs, and SHA-256 mismatch.

The runtime connection is `chimera_app` on `chimera`; tests use `chimera_test_app` on `chimera_test`. Grant inspection found no cross-database, global, or prohibited administrative privileges. Session files use an application-owned non-public directory when `SESSION_SAVE_PATH` is not explicitly configured, which avoids relying on an unwritable XAMPP temporary directory on Windows.

One Phase 1 consistency defect was corrected: login activity is now committed before the authenticated session is established. Previously, an activity-write failure could return an error after session authentication had already been set.

## Assumptions

The database account has only the permissions needed by the selected schema. HTTPS termination is handled by the host. HSTS is deferred until HTTPS is verified to avoid locking out a misconfigured deployment.

## Phase 8 analytics boundary

Analytics is an exact-role Security Admin read boundary. It projects safe evidence fields, uses allowlisted filters and prepared statements, bounds every list/export, and neutralizes spreadsheet formula prefixes. It cannot write historical evidence, invoke scoring/adaptation, change lab state, or read password, cookie, raw-session, token-hash, document-content, or internal-path material.

## Production modes

Normal mode disables `/lab/*`; authorized lab mode exposes only controlled synthetic modules and produces a private readiness warning. Production always suppresses verbose errors. Direct HTTPS indicators govern HSTS/redirects; forwarded headers remain untrusted. Secure cookies, CSRF, RBAC, owner scoping, private storage, and telemetry privacy remain identical in both modes.
