# Testing

## Automated checks

`php tests/run.php` verifies the Phase 1 foundation: password hashing, session regeneration, registration role assignment, CSRF route placement, role guards, headers, PDO configuration, and required schema tables.

`php tests/phase2.php` verifies profile validation, upload size/type/MIME controls, randomized filenames, traversal prevention, route parameters, ownership query structure, CSRF placement, API authorization, activity privacy, role separation, mass-assignment resistance, and download integrity checks.

`php tests/database_verify.php` performs read-only development connection, schema, seed, account, and grant checks. `php tests/integration.php` is gated by the exact `TEST_DB_DATABASE=chimera_test` value and dedicated test credentials. It verifies server/database/account metadata before using a transaction that is rolled back. `php tests/http_e2e.php` performs real HTTP workflows against `chimera_test`, cleans up its exact fixture IDs/files, and refuses unsafe database configuration.

`php tests/phase3.php` verifies taxonomy, deterministic severity, metadata sanitization, direct-peer attribution, fail-safe recording structure, exact Security Admin route guards, bounded reads, and the absence of scoring calculations. The HTTP E2E suite additionally verifies persisted telemetry, dashboard/API RBAC, event safety, source context, and preservation of existing secure responses.

`php tests/phase4.php` verifies CHIMERA token namespacing, hash-registry validation, active decoy resolution, centralized event recording, exact-role management routes, data isolation, and the absence of scoring, blocking, exploitation, or command execution. HTTP E2E inserts configuration only into `chimera_test`, exercises public synthetic routes and token triggering, verifies linked events and RBAC, then deletes its exact fixtures.

`php tests/phase6.php` verifies exact score/profile boundaries, profile richness, registered-marker policy, zero-score adaptation telemetry, LOW fallback, no-downgrade stability, repeat-render deduplication, RBAC, application isolation, and the Phase 7 boundary. `php tests/phase6_integration.php` exercises the same policy against `chimera_test`, reconstructs transitions, checks metadata safety, and removes its exact fixtures.

`php tests/phase7.php` verifies the default-off switch, explicit route gate, bounded module designs, CSP sandbox, state-control middleware, zero-score telemetry, and prohibited primitives. `php tests/phase7_integration.php` verifies SQLi/IDOR/XSS comparisons, state history, data isolation, and assessment isolation against `chimera_test`. `php tests/phase7_http_e2e.php` runs separate disabled and enabled HTTP servers, performs the vulnerable/countermeasure/retest workflow, checks RBAC and CSRF, and removes its exact fixtures.

Run:

```powershell
php tests/run.php
php tests/phase2.php
php tests/phase3.php
php tests/phase4.php
php tests/phase5.php
php tests/phase5_integration.php
php tests/phase6.php
php tests/phase6_integration.php
php tests/phase7.php
php tests/phase7_integration.php
php tests/phase7_http_e2e.php
php tests/database_verify.php
php tests/integration.php
php tests/http_e2e.php
Get-ChildItem -Recurse -Filter *.php | ForEach-Object { php -l $_.FullName }
```

## Dedicated database setup

Create a disposable `chimera_test` database, import `database/schema.sql`, and configure `TEST_DB_DATABASE=chimera_test`, `TEST_DB_USERNAME`, and `TEST_DB_PASSWORD` in the ignored local `.env`. Do not seed or reuse the application/development database for integration testing. The verified local server is MariaDB 12.2.2 on port 3308; port 3306 is not used by CHIMERA.

No test attempts to discover, guess, reset, or change database credentials.

## Manual Phase 1 checks

1. Registration creates only a User and regenerates the session ID.
2. Valid and invalid login produce appropriate redirects and generic errors.
3. Logout rejects missing/invalid CSRF and destroys the authenticated session.
4. User cannot access `/admin` or `/security`.
5. Admin can access `/admin` but receives 403 at `/security`.
6. Security Admin can access `/security` but receives 403 at `/admin`.
7. Unauthenticated protected access redirects to `/login`.
8. Production mode shows generic errors and logs details outside the public root.

## Manual Phase 2 checks

1. User A can list, view, download, and delete Document A.
2. User A receives 404 for Document B owned by User B in both HTML and API flows.
3. Upload rejects oversized, disallowed-extension, and MIME-mismatched files.
4. A stored file is outside the web root and cannot be fetched directly.
5. Profile updates cannot change email, ID, role, or activation state.
6. User activity exposes only the signed-in account's rows.
7. Admin can open `/admin`; User and Security Admin receive 403.
8. User can call owner-scoped API resources; unauthenticated API calls receive JSON 401.
9. Deleting a missing stored file removes the stale owned record safely.
10. Simulated database failure during deletion restores the quarantined file.

## Phase 2.5 result on 2026-09-30

- Phase 1 regression: 22 passed, 0 failed
- Phase 2 unit/static: 26 passed, 0 failed
- Test database preflight: 6 passed, 0 failed
- Database ownership/activity integration: 8 passed, 0 failed, 0 skipped
- Real HTTP/E2E: 50 passed, 0 failed, 0 skipped
- PHP lint: 62 files passed, 0 failed
- Dangerous application command primitives: none found
- Active Phase 3 behavior at the Phase 2.5 checkpoint: none found
- Development database verifier: 18 passed, 0 failed
- Authorized fixture cleanup: exactly 2 synthetic accounts, 3 dependent document rows, 7 dependent activity rows, and 3 corresponding private files removed; seed and configuration records remained unchanged

All application-security flows and Phase 2.5 completion gates pass. A forced database-failure restoration path and symbolic-link creation are reviewed in code but were not fault-injected on this Windows run.

## Phase 3 result on 2026-09-30

- Phase 3 static/security checks: 17 passed, 0 failed
- HTTP/E2E including telemetry: 71 passed, 0 failed
- Phase 1 regression: 22 passed, 0 failed
- Phase 2 regression: 26 passed, 0 failed
- Development database verifier: 20 passed, 0 failed after Phase 4 seed-policy checks
- Database integration: 7 preflight and 8 ownership/activity checks passed, 0 failed
- PHP lint: 68 files passed, 0 failed
- Telemetry uses `chimera_test` during destructive E2E and removes events created by the run
- Threat scoring, adaptive response, deception, honeytoken activation, and vulnerability-lab behavior remain absent

## Phase 4 result on 2026-09-30

- Phase 4 static/boundary checks: 15 passed, 0 failed
- HTTP/E2E including static deception: 85 passed, 0 failed
- Phase 1 regression: 22 passed, 0 failed
- Phase 2 regression: 26 passed, 0 failed
- Development database verifier: 20 passed, 0 failed
- Integration preflight: 7 passed, 0 failed; ownership/activity: 8 passed, 0 failed
- Phase 3 regression: 17 passed, 0 failed
- PHP lint: 81 files passed, 0 failed
- Development seed: 3 decoys and 2 CHIMERA-format hashed honeytokens verified
- No threat scoring, adaptive activation, automated response, lab route, or dangerous execution primitive introduced

## Phase 5 result on 2026-09-30

- Phase 5 policy/boundary checks: 20 passed, 0 failed
- Phase 5 database integration: 11 passed, 0 failed
- HTTP/E2E including assessment: 92 passed, 0 failed
- Phase 1 regression: 22 passed, 0 failed
- Phase 2 regression: 26 passed, 0 failed
- Development database verifier: 20 passed, 0 failed
- Integration preflight: 7 passed, 0 failed; ownership/activity: 8 passed, 0 failed
- Phase 3 regression: 17 passed, 0 failed
- Phase 4 regression: 15 passed, 0 failed
- PHP lint: 90 files passed, 0 failed
- Dangerous execution primitive scan: no matches
- Phase 6 response-coupling boundary scan: no matches
- Correlation, expiry, actor/source isolation, idempotency, bounds, classification, and explainability verified
- Assessment APIs omit internal identifiers and secrets
- No adaptive deception, automatic blocking, account action, document mutation, or score-driven response introduced

## Phase 6 result on 2026-09-30

- Phase 6 policy/boundary checks: 24 passed, 0 failed
- Phase 6 database integration: 13 passed, 0 failed
- HTTP/E2E including LOW to CRITICAL adaptive progression: 99 passed, 0 failed
- Phase 1 regression: 22 passed, 0 failed
- Phase 2 regression: 26 passed, 0 failed
- Development database verifier: 20 passed, 0 failed
- Integration preflight: 7 passed, 0 failed; ownership/activity: 8 passed, 0 failed
- Phase 3 regression: 17 passed, 0 failed
- Phase 4 regression: 15 passed, 0 failed
- Phase 5 regression: 20 passed, 0 failed
- Phase 5 database integration: 11 passed, 0 failed
- PHP lint: 98 files passed, 0 failed
- Dangerous execution primitive scan: no matches
- Phase 7 active-behavior scan: no matches
- Legitimate application score-coupling scan: no matches
- Post-E2E integration rerun found no residual fixtures or telemetry
- No test was skipped

## H-18 final production closure — two-user document ownership

The operator completed the separately authorized production workflow using the retained H11 synthetic USER as USER A and exactly one newly registered synthetic USER B. USER B was assigned role `user`; normal logout succeeded, and subsequent protected-page access required authentication. No ADMIN or Security Admin account acted as either ownership-test user.

USER A uploaded one harmless 94-byte text document, saw it in the owner-scoped listing and details page, and downloaded byte-identical content. USER B's listing excluded the document. USER B then made exactly three deliberate cross-owner requests: HTML detail, download, and deletion with a valid USER B CSRF token. Each returned the safe generic HTTP 404 ownership response. A preliminary malformed manual request returned HTTP 405, created no ownership-denial event, and is not counted as ownership evidence.

After the three denials, USER A still saw the document, retained its metadata and integrity information, and downloaded byte-identical content. USER A then deleted it legitimately. The temporary USER B-owned document used to obtain a normal valid-CSRF delete form was also deleted legitimately. No H18 production document intentionally remains.

Read-only production telemetry showed exactly three `OWNERSHIP_ACCESS_DENIED` events for:

- `GET /documents/1`;
- `GET /documents/1/download`;
- `POST /documents/1/delete`.

Security Analytics reported exactly 3 events / 36 points. This matches the locked +12 rule and classifies as MEDIUM under the 20–44 threshold. No HIGH/CRITICAL session, deception interaction, honeytoken interaction, or controlled-LAB activity resulted. The legitimate owner deletion was separately recorded as zero-weight `DOCUMENT_DELETE` success evidence.

H18-G01–G03 are closed by the dedicated local workflow, comprehensive immutable snapshots, response-equivalence checks, and production owner control. H18-G04 remains intentionally assigned to H19 and does not block H18. H18-G05 remains a non-blocking resilience/retention observation: normal cleanup and rollback restoration passed locally, while invasive post-commit unlink-failure injection was not performed.

No H18 runtime-code, schema, configuration, route, production SQL, or deployment change was required. H13 privacy, H14 scoring, H15 deception/adaptive, H16 analytics/export, H17 CSRF, and LAB isolation/default-disabled invariants remain preserved.

**H-18 = PASS. Gate H = 18/20 (90%). H-19 and H-20 are NOT STARTED.**

## H-19 storage denial after workflow — local validation checkpoint

Dedicated H19 suites:

```powershell
php tests/h19_storage_denial.php
php tests/h19_storage_denial_integration.php
php tests/h19_storage_denial_http_e2e.php
```

Local evidence on 2026-10-07:

- static storage-policy/topology checks: 34 passed, 0 failed, 0 skipped;
- guarded `chimera_test` storage integration: 16 passed, 0 failed, 1 skipped;
- local HTTP/E2E owner/direct-path workflow: 16 passed, 0 failed, 0 skipped;
- focused H19 total: 66 passed, 0 failed, 1 skipped;
- established supporting regression: 898 passed, 0 failed, 0 skipped;
- executed canonical aggregate including H19: 964 passed, 0 failed, 1 skipped;
- PHP lint: 160/160 passed;
- repository secret, dangerous-primitive, route/RBAC, error-disclosure, LAB-isolation/default-disabled, analytics-read-only, H13–H18, and InfinityFree artifact/security checks: PASS;
- exact database, active-file, symlink, and trash-fixture cleanup: PASS; expected 11-table `chimera_test` schema intact.

The single skip is explicit and bounded: Windows did not permit creation of the optional local symlink fixture under the current privilege/filesystem policy. Static symlink rejection remained present, and no assertion was weakened.

Static validation proved that the root storage denial uses `[F,L,NC]` before public handling, asset mapping, file/directory bypass, and front-controller routing; covers storage roots, descendants, trash, case variation, and PATH_INFO; and retains directory-index, dotfile, sensitive-file, direct-`public/`, and executable-extension controls. `storage/.htaccess` and `storage/uploads/.htaccess` retain total denial and `Options -Indexes`, and the deployment manifest includes both policies and the active/trash topology.

Integration validation proved absolute private-root confinement outside `public/`, 48-lowercase-hex internal names with allowlisted extensions, independence from original names, rejection of traversal/separators/arbitrary extensions/malformed names, rejection of relative or public-root configuration, byte/checksum integrity, trash confinement, rollback restoration, normal deletion cleanup, no positive contributor, and unchanged LAB state.

The local HTTP workflow proved owner upload/list/detail/download/delete behavior, byte-identical downloads, absence of storage names/paths/direct links in HTML and APIs, zero-weight sanitized workflow telemetry, and no deception/honeytoken/LAB activity. A direct `/storage/...` request through the PHP development-server harness returned a safe CHIMERA 404 with no sentinel or error disclosure and no telemetry. This is deliberately **not** treated as evidence of InfinityFree Apache `.htaccess` enforcement.

H19-G01, G02, G03, and G06 remain production-dependent. G04's inherited denial was verified statically but still depends on provider enforcement. G05 is covered by upload allowlisting, executable-name rejection, constrained internal extensions, and Apache policy declarations; no vulnerability or runtime remediation was established. G07 rollback restoration and ordinary trash cleanup passed; invasive post-commit unlink-failure injection remains a non-blocking resilience observation.

No H19-Fxx defect was discovered. Runtime application code, schema, configuration, routes, and denial policies were unchanged. Production was not accessed or modified.

The next separately authorized production checkpoint is one retained standard USER, one harmless text fixture, one narrowly scoped read-only lookup of only that fixture's internal storage name, exactly one known direct-file request, at most one known storage-directory request, owner download/integrity recheck, and legitimate cleanup. No scanning, enumeration, or executable fixture is required.

**H-19 = LOCAL VALIDATION COMPLETE / PRODUCTION PENDING. Gate H remains 18/20 (90%). H-20 is NOT STARTED.**

### H-19 production evidence and final closure

The operator completed the bounded provider-boundary validation using the retained H11 standard USER and one harmless temporary text document. No new account was created. The fixture was document ID 3 and passed normal upload, owner listing, details, application-controlled download, and content-integrity controls before direct-storage testing.

One scoped read-only production lookup returned the fixture's ID, original name, and internal storage name. Exactly one row matched. The internal name was used privately only to construct the known direct target and is not recorded in repository evidence. No production mutation SQL was executed.

From a private browser context, the exact known-existing private file beneath `/storage/uploads/documents/` returned the InfinityFree provider HTTP 403 page. It did not fall through to CHIMERA, return a CHIMERA-styled 404, or disclose the fixture sentinel, document bytes, directory content, filesystem paths, warnings, stack traces, application details, credentials, sessions, CSRF material, or source-correlation information. One exact request to `/storage/uploads/documents/` also returned provider HTTP 403 with no index, filename, generated name, timestamp, metadata, or sensitive disclosure.

No scanning, enumeration, recursive probing, encoded-path mutation, executable fixture, LAB action, decoy, honeytoken, or provider-infrastructure test occurred. After the two denials, the owner downloaded the fixture normally and confirmed unchanged content. The fixture was then deleted through CHIMERA's normal owner workflow and disappeared from the listing. No direct storage or SQL cleanup was used.

Because Apache/provider denial occurs before `public/index.php`, the correct expected CHIMERA effect for both direct requests is zero application security events, zero contributors, and zero score change. Ordinary owner upload/download/delete activity may remain zero-weight. No additional application telemetry was required as provider-boundary proof.

H19-G01, G03, and G06 are satisfied by the known-existing-file lookup and live provider 403 evidence. G02 remains a documented but non-blocking local-fidelity limitation. G04 remains a non-blocking defense-in-depth observation: inherited denial was statically validated and the deployed storage subtree was denied. G05 remains optional future hardening with no demonstrated bypass. G07 remains a non-blocking resilience observation; ordinary cleanup and rollback passed, while invasive unlink-failure injection was intentionally omitted.

No H19-Fxx defect or remaining H19 blocker exists. H13–H18 invariants remain preserved. Runtime code, schema, configuration, routes, root/storage policies, and production configuration were unchanged; no production patch was required.

**H-19 = PASS. Gate H = 19/20 (95%). H-20 is NOT STARTED.**

## H-20 final Gate H assurance regression

Final local verification on 2026-10-07 reran every existing suite through H19:

- canonical total: **964 passed, 0 failed, 1 skipped**;
- PHP lint: **160/160 passed**;
- repository secret scan: **0 findings**;
- fixture cleanup and expected 11-table `chimera_test` schema: PASS;
- dangerous-primitive, route/RBAC, error-disclosure, analytics-read-only, LAB-isolation/default-disabled, deployment-artifact, H13 privacy, H14 scoring, H15 deception/privacy, H16 analytics/export, H17 CSRF, H18 ownership, and H19 storage checks: PASS.

The one skip remains the documented optional Windows symlink-creation test. It is non-blocking because fixture creation was prevented by local OS policy, no assertion was weakened, and storage name validation, symlink rejection logic, denial policies, and the accepted live provider known-file 403 remain covered.

No H20-Fxx blocker was found. H01–H19 evidence remains internally consistent. Current sources retain the approved telemetry privacy, deception privacy, analytics/export, and malformed-CSRF remediations. No runtime application, schema, route, configuration, scoring, role, `.htaccess`, deployment-manifest, LAB, or production change occurred during H20. Production was not accessed.

Residual observations remain classified as accepted historical-data risk, provider/test-environment limitations, optional future hardening, or resilience observations; none invalidates the baseline. The detailed 20-checkpoint matrix and classifications are recorded in [GATE_H_VALIDATION.md](GATE_H_VALIDATION.md).

**H-20 = PASS. Gate H = 20/20 (100%). H01–H20 = PASS. Gate H = CLOSED.**

**Next state: PRE-PENTEST BASELINE READY FOR FREEZE REVIEW.**

## Phase 9 production-hardening verification

```powershell
php tests/phase9.php
php tests/phase9_integration.php
php tests/phase9_http_e2e.php
php scripts/scan-secrets.php
php scripts/check-deployment-readiness.php
```

The readiness CLI is expected to return FAIL for an intentionally incomplete/local configuration; execute it with planned production environment values for a deployment decision. It never prints secret values.

### Phase 9 result on 2026-09-30

- Phase 9 unit/static/configuration checks: 38 passed, 0 failed
- Phase 9 database integration: 13 passed, 0 failed
- Phase 9 HTTP/E2E, including controlled DB error disclosure: 18 passed, 0 failed
- Complete Phase 1–9 automated checks: 490 passed, 0 failed, 0 skipped
- PHP lint: 138 files, 0 failures
- Repository secret scan: passed; no high-confidence committed secret found
- Dangerous primitive, LAB isolation, analytics read-only, route security, production error, controller coupling, and Phase 10 behavior reviews: passed
- Post-E2E integration: no residual fixtures

## Phase 10 preparation verification

Run locally before any hosting action:

```powershell
php tests/phase10.php
php scripts/phase10-hosting-preflight.php
```

`tests/phase10.php` verifies the exact source-required extension list, missing-extension blocking, unresolved-hosting classification, CLI-only/no-network behavior, secret-safe output, ordered deployment stages, NORMAL_SAFE checkpoint, separately authorized lab gate, and scoped pentest/evidence documentation.

The hosting preflight is expected to report `HOSTING-DEPENDENT` until it runs in an authorized hosting context. The production-readiness portion may report `BLOCKED` under local development values; this is correct and must not be converted into a passing deployment result.

Phase 10 preparation result on 2026-09-30:

- Phase 1–9 baseline: 490 passed, 0 failed, 0 skipped
- PHP lint: 138 files passed, 0 failed
- Repository secret scan: passed
- Phase 10 preparation: 20 passed, 0 failed
- Local capability preflight: 15 VERIFIED, 8 HOSTING-DEPENDENT, 0 BLOCKED
- Production readiness under the current local configuration: BLOCKED (16 PASS, 0 WARNING, 6 FAIL)
- External deployment/live checks: BLOCKED ON DEPLOYMENT ACCESS, not executed
- No Hostinger connection, upload, database initialization, DNS/certificate action, lab activation, or pentest occurred

## Phase 10 InfinityFree compatibility verification

```powershell
php tests/phase10_infinityfree.php
php tests/phase10_infinityfree_integration.php
```

- InfinityFree routing, private-path, protected-storage, seed, template, checker, denial-canary, and manifest checks: 44 passed, 0 failed
- Production-reference seed integration against exact `chimera_test`: 9 passed, 0 failed
- Complete Phase 1–10 local regression: 563 passed, 0 failed, 0 skipped
- PHP lint: 144 passed, 0 failed
- Repository secret scan: passed
- Dangerous primitive scan: passed
- LAB real-data/I/O isolation: passed
- Legitimate-controller coupling: passed
- Analytics read-only scan: passed
- Production external-I/O scan: passed
- Production artifact-leakage scan: passed
- Post-regression integration cleanup: no residual E2E, telemetry, deception, LAB, or reference-seed fixtures

These results authorize no external action. InfinityFree PHP/extensions, database port, `.htaccess` behavior, HTTPS indicators, permissions, and headers remain hosting/live-verification pending.

## H13 telemetry privacy remediation verification

`php tests/h13_privacy.php` verifies that `REMOTE_ADDR` remains only a transient direct-peer input, forwarded headers remain ignored, HMAC-SHA-256 correlation remains deterministic, legacy raw-source metadata is removed at presentation boundaries, telemetry and deception output expose no raw or replacement source identifier, deterministic scoring remains described accurately, forbidden metadata filtering remains active, and the InfinityFree `$_ENV` precedence behavior is preserved.

The complete local Phase 1–10 regression after this remediation passed 584 checks with 0 failures and 0 skips. PHP lint passed for 145 files. The repository secret scan and the existing dangerous-primitive, route-security, production-error-disclosure, LAB-isolation, analytics-read-only, and production-artifact-leakage checks passed. The final integration cleanup check found no residual E2E, telemetry, deception, or LAB fixtures in `chimera_test`.

No schema migration or production action is part of this remediation. Historical production rows are handled defensively on presentation; any later persisted-data cleanup requires separate authorization after the application patch is deployed and verified.

The subsequent operator-assisted production deployment and sanitized H13 closure evidence are recorded in [GATE_H_VALIDATION.md](GATE_H_VALIDATION.md). H-13 is PASS; 39 historical rows remain intentionally unchanged in storage.

## H14 threat-scoring sanity validation

Run:

```powershell
php tests/h14_scoring.php
php tests/h14_scoring_integration.php
```

The static suite locks the exact ten-rule positive scoring set, every approved weight, zero-weight behavior for all other taxonomy events, score bounds, all classification edges, and the no-automated-action boundary. The integration suite runs only against `chimera_test` and verifies every positive rule's event/contributor/session consistency, zero-weight correlation, deterministic repeated-event accumulation, same-event idempotency, same-decoy suppression, saturation, actor/window isolation, LAB exclusion, and exact fixture cleanup.

Local result on 2026-10-05:

- H14 static: 37 passed, 0 failed, 0 skipped
- H14 integration: 21 passed, 0 failed, 0 skipped
- Required focused/supporting regression: 311 passed, 0 failed, 0 skipped
- Complete Phase 1–10 plus H13/H14 regression: 642 passed, 0 failed, 0 skipped
- Direct transaction-failure injection: not exercised because it would require an invasive trigger, schema change, or application seam; transaction and concurrent-linkage guards remain statically covered
- Production H14-P1 contributor integrity: PASS — 23 contributors; all mismatch/invalid/unattached counts zero
- Production H14-P2 session reconstruction: PASS — 16 sessions; all range, reconstruction, classification, and request-count mismatch counts zero
- Production H14-P3 event/correlation/privacy integrity: PASS — 41 events; all scoring/correlation/LAB/malformed-identifier counts zero; historical raw-source-key count remains 39

H-14 is PASS based on the local regression plus operator-supplied read-only production aggregates. Gate H is 14/20 (70%), and H-15 is not started. See [GATE_H_VALIDATION.md](GATE_H_VALIDATION.md).

## H15 deception/privacy local remediation verification

Run the focused suites against the local repository and guarded `chimera_test` database:

```powershell
php tests/h15_deception.php
php tests/h15_deception_integration.php
```

The static suite verifies the common adaptive presentation sanitizer, honeytoken query minimization, preserved safe metadata, fixed LOW/MEDIUM/HIGH/CRITICAL policy, scoring invariants, exact Security Admin route guards, absence of dangerous deception primitives, legitimate-data isolation, and default-disabled LAB configuration.

The integration suite installs only exact local fixtures in `chimera_test`. It verifies that both adaptive API model payloads sanitize legacy raw and replacement source fields, honeytoken inventory/recent-event output is minimized, normal honeytoken linkage remains consistent, decoy scoring and repeat suppression remain unchanged, adaptive decisions remain zero-weight, and users, roles, documents, and LAB state remain unchanged. It deletes all exact fixtures afterward.

Local result on 2026-10-06:

- H15 static/privacy: 31 passed, 0 failed, 0 skipped
- H15 integration/privacy: 16 passed, 0 failed, 0 skipped
- Focused H15 total: 47 passed, 0 failed, 0 skipped
- Requested supporting regression: 351 passed, 0 failed, 0 skipped
- Complete canonical regression: 689 passed, 0 failed, 0 skipped
- HTTP/E2E: 100 passed, 0 failed
- PHP lint: 149/149 passed
- Repository secret scan: PASS
- Dangerous-primitive, route/RBAC, error-disclosure, LAB-isolation, analytics-read-only, InfinityFree artifact/security, H13 privacy, and H14 scoring checks: PASS
- H15 test fixture cleanup: PASS

Operator-supplied production H15-P1/P2/P3 baseline aggregates passed before this local remediation. Production has three expected active decoys, two expected active honeytokens, no intentional decoy/honeytoken/adaptive interactions, no reported integrity mismatches, and exactly 39 historical legacy raw-source-key rows. The historical rows were not changed, and no production events were generated.

H15-G02 remains an observation: the security-event/session transaction and honeytoken linkage transaction are separate. The normal linkage path passed locally; invasive transaction-failure injection was not performed.

The approved two-file production model patch was subsequently deployed by the operator. Post-patch public boot/static/LAB-disabled sanity passed; Security Admin deception and adaptive dashboards loaded normally; the read-only deception/adaptive APIs matched the P1/P2/P3 baseline and exposed no prohibited source, hash, marker-material, or credential fields.

Production contained no intentional decoy, honeytoken, or adaptive interactions. The adaptive-session detail endpoint was therefore not dynamically exercised, and no event was manufactured merely to create a record. Its shared presentation boundary is covered by the focused local legacy-fixture regression.

Exactly 39 historical rows retain the legacy raw-source metadata key. They remain intentionally untouched and are sanitized at presentation boundaries. H15 generated no intentional production deception event and performed no historical cleanup.

**H-15 = PASS. Gate H = 15/20 (75%). H-16 is not started.**

## H16 analytics and evidence-export local remediation

Run:

```powershell
php tests/h16_analytics.php
php tests/h16_analytics_integration.php
```

The H16 static suite verifies exact Security Admin authorization, fail-closed filters, paired bounded dates, export-specific filter contracts, source-identifier exclusion, deterministic ordering, per-export limits, read-only dependencies, CSV formula neutralization, unchanged scoring, and default-disabled LAB behavior. The guarded integration suite uses only `chimera_test` and verifies deterministic aggregates, 200-row timeline and 1,000-row export bounds, equal-timestamp ordering, legacy-source sanitization across session/event JSON and CSV output, invalid-filter isolation, empty results, database immutability, and exact fixture cleanup.

Local result on 2026-10-06:

- H16 static/privacy: 40 passed, 0 failed, 0 skipped
- H16 integration/privacy: 22 passed, 0 failed, 0 skipped
- Focused H16 total: 62 passed, 0 failed, 0 skipped
- Phase 8 HTTP/E2E: 25 passed, 0 failed, including the exact generic `session_evidence` request and role/privacy contract
- Complete canonical regression including H16-F06: 751 passed, 0 failed, 0 skipped
- PHP lint: 151/151 passed
- Repository secret, dangerous-primitive, route/RBAC, error-disclosure, LAB-isolation, analytics read-only, H13 privacy, H14 scoring, H15 deception/privacy, and InfinityFree artifact/security checks: PASS
- H16 fixture cleanup: PASS

H16-F01 through H16-F05 were remediated locally. Internal correlation hashes are no longer selected or presented by analytics session surfaces; malformed filters cannot broaden results; dates require a paired maximum-366-day range; exports enforce per-type filter semantics; and every export type now has an explicit 1,000-row maximum. No schema, scoring, classification, deception/adaptive, LAB, or production state changed.

H16-F06 was subsequently reproduced after the first production patch: the dashboard emitted `/api/security/analytics/export?type=session_evidence&format=json`, while the backend required an unstated positive `session_id` and returned `INVALID_EXPORT` when it was absent. The local contract now accepts the exact dashboard URL and exports exactly one deterministic latest sanitized session, or an empty data array when no session exists. An explicit positive `session_id` still selects that session; malformed IDs, unsupported types, and incompatible filters remain fail-closed.

Operator-supplied pre-patch read-only baselines were recorded without rerunning production SQL: 45 events, 20 sessions, 26 contributors, no decoy/honeytoken/adaptive/LAB events, and 39 historical rows retaining the legacy raw-source metadata key. Those 39 rows remain intentionally untouched.

The operator subsequently deployed only `SecurityAnalyticsService.php` and `SecurityAnalyticsApiController.php`. Public boot, analytics-dashboard, and disabled-LAB sanity passed. The exact generic Security Admin export request returned HTTP 200 JSON with one bounded existing session, consistent score reconstruction, minimized metadata, no prohibited source/correlation or secret material, no HTTP 500, and no mutation. The historical 39-row raw-source-key baseline remained intentionally untouched.

**H-16 = PASS. Gate H = 16/20 (80%). H-17 is not started.**

## H-17 CSRF negative control — local remediation and validation

H17-F01 was confirmed in `VerifyCsrf`: casting an array-valued `_token` to string could emit an `Array to string conversion` warning before the request was rejected. The minimal local remediation now reads the submitted value as mixed, requires `is_string()`, and calls `Csrf::valid()` only for a string. HTTP 419, `CSRF_REJECTED` telemetry, the exact +12 score, authentication/RBAC precedence, and valid-token behavior are unchanged.

Focused suites:

```powershell
php tests/h17_csrf.php
php tests/h17_csrf_integration.php
php tests/h17_csrf_http_e2e.php
```

Local result on 2026-10-06:

- H17 static/route/privacy: 32 passed, 0 failed, 0 skipped
- H17 integration/scoring/privacy: 12 passed, 0 failed, 0 skipped
- H17 HTTP/E2E: 29 passed, 0 failed, 0 skipped
- Focused H17 total: 73 passed, 0 failed, 0 skipped
- Supporting established regression: 751 passed, 0 failed, 0 skipped
- Complete canonical regression including H17: 824 passed, 0 failed, 0 skipped
- PHP lint: 154/154 passed
- Repository secret scan: PASS
- Dangerous-primitive, route/RBAC, production error-disclosure, LAB-isolation/default-disabled, analytics read-only, H13 privacy, H14 scoring, H15 deception/privacy, H16 analytics/export privacy, and InfinityFree artifact/security checks: PASS
- Exact `chimera_test` and private-file fixture cleanup: PASS

The focused tests enumerate all seven business-state-changing POST routes, verify their exact authentication/role-before-CSRF pipelines and shared form helper, and exercise missing, incorrect, malformed, array-valued, and stale tokens. Rejected registration, login, logout, profile, upload, deletion, and Security Admin LAB-state requests produced no protected-state mutation. Eight deliberate HTTP rejections created exactly eight `CSRF_REJECTED` events and eight contributors of +12 each; correlation, score bounds, and classification remained consistent.

A unique invalid-token sentinel was absent from event metadata, contributor evidence, the Security Admin dashboard, telemetry APIs, analytics APIs, and JSON evidence exports. Raw/internal source identifiers, credentials, cookies, authorization data, CSRF material, and session-secret fields remained excluded. Representative valid registration/login, profile, document, logout, and guarded local module-state workflows continued to work. The vulnerability LAB remained globally disabled.

No schema, route, scoring, role, deception/adaptive, analytics/export, or configuration change was made. The accepted H-08 production 419 evidence remains sufficient as the production negative-control observation; no new production rejection request was required.

The operator subsequently retained a rollback copy and deployed only `app/Middleware/VerifyCsrf.php` to its matching production runtime path. Post-deployment checks for `/`, `/about`, and `/login` rendered normally with no HTTP 500, PHP warning, or blank page. A legitimate authenticated Security Admin `POST /profile` using the normal UI token succeeded and displayed `Your profile was updated.` The account remained authenticated, and the valid request produced neither HTTP 419 nor an unexpected error. No new negative-CSRF production request was performed.

The production patch and positive control, the previously accepted H-08 production negative control, and the complete local H17 evidence jointly close the stage. No production SQL, schema/configuration/route change, LAB enablement, or additional negative telemetry was required.

**H-17 = PASS. Gate H = 17/20 (85%). H-18 is NOT STARTED.**

## H-18 two-user document ownership — local validation checkpoint

Dedicated H18 suites:

```powershell
php tests/h18_document_ownership.php
php tests/h18_document_ownership_integration.php
php tests/h18_document_ownership_http_e2e.php
```

Local evidence on 2026-10-07:

- static route/ownership/storage checks: 34 passed, 0 failed, 0 skipped;
- guarded `chimera_test` integration: 8 passed, 0 failed, 0 skipped;
- two-user HTTP/E2E workflow: 32 passed, 0 failed, 0 skipped;
- focused H18 total: 74 passed, 0 failed, 0 skipped;
- established supporting regression: 824 passed, 0 failed, 0 skipped;
- complete canonical result including H18: 898 passed, 0 failed, 0 skipped;
- PHP lint: 157/157 passed;
- repository secret, dangerous-primitive, route/RBAC, error-disclosure, LAB-isolation/default-disabled, analytics-read-only, H13 privacy, H14 scoring, H15 deception/privacy, H16 analytics/export privacy, H17 CSRF, and InfinityFree artifact/security checks: PASS;
- exact H18 database, active-file, and trash-fixture cleanup: PASS.

The HTTP suite authenticated two isolated USER accounts, uploaded exactly one harmless USER A document, proved owner-only HTML/API listing, detail and download behavior, and verified downloaded bytes against the fixture digest. USER B received safe generic 404 responses for HTML detail, download, API detail, and valid-CSRF deletion. Each denial preserved the complete document row, ownership, metadata, checksum, file bytes, active storage, trash state, legitimate activity, unrelated business records, and LAB state.

The primary four-request denial sequence created exactly four `OWNERSHIP_ACCESS_DENIED` events and four matching +12 contributors. The correlated session reached score 48/HIGH. Separate nonexistent-ID equivalence probes were intentionally isolated from that primary assertion; all four response pairs were equivalent and the eight total deliberate local denials accumulated to 96/CRITICAL without exceeding the 0–100 bound. No `CSRF_REJECTED` event substituted for the valid-CSRF ownership denial.

Telemetry UI, telemetry API, analytics API, security-event export, and explicit session-evidence export exposed no raw/internal source identifier, private filename/path, checksum, document content, owner PII, credential, cookie, authorization-header, CSRF, or session-secret material. USER A retained byte-identical access after all denials and then deleted the document legitimately; the row and active file were removed, one deletion activity was recorded, no owner-denial event was added, and no trash fixture remained.

H18-G01 through H18-G03 are covered by the authoritative workflow, immutable snapshots, and cross-owner/nonexistent equivalence assertions. H18-G04 remains explicitly reserved for H19 live direct-storage denial validation. H18-G05 normal cleanup and rollback restoration passed; invasive post-commit unlink-failure injection was not introduced, so private orphan cleanup remains a non-blocking resilience/retention observation.

No H18-Fxx application defect was discovered. Application runtime code, schema, configuration, and routes were unchanged. Production was not accessed or modified. A separately authorized minimal production workflow remains required before H18 closure.

**H-18 = LOCAL VALIDATION COMPLETE / PRODUCTION PENDING. Gate H remains 17/20 (85%). H-19 and H-20 are NOT STARTED.**

## Phase 8 analytics verification

Run the dedicated suites against the isolated test database:

```powershell
php tests/phase8.php
php tests/phase8_integration.php
php tests/phase8_http_e2e.php
```

`phase8.php` verifies metric formulas, N/A semantics, safe identifiers, filters, RBAC route declarations, bounded queries, read-only coupling, export allowlists, data minimization, and all four CSV formula prefixes. `phase8_integration.php` installs timestamped deterministic evidence only in `chimera_test`, verifies exact aggregates and score/timing reconstruction, then deletes it. `phase8_http_e2e.php` produces operational and LAB evidence through actual HTTP flows, exercises Security Admin UI/APIs/exports and role denials, snapshots score immutability, and verifies zero residual fixtures.

Both database suites abort unless the active database is exactly `chimera_test`, port is 3308, and the account is `chimera_test_app`.

### Phase 8 result on 2026-09-30

- Phase 8 unit/static/boundary checks: 35 passed, 0 failed
- Phase 8 deterministic database integration: 24 passed, 0 failed
- Phase 8 HTTP/E2E: 18 passed, 0 failed
- Phase 1: 22/22; Phase 2: 26/26; Phase 3: 17/17; Phase 4: 15/15
- Phase 5: 20/20 and integration 11/11
- Phase 6: 24/24 and integration 13/13
- Phase 7: 25/25, integration 14/14, and HTTP/E2E 22/22
- Existing full HTTP/E2E: 99/99
- Development database verifier: 21/21
- Integration preflight: 7/7; ownership/activity: 8/8
- PHP lint: 123 files, 0 failures
- Dangerous primitive, LAB isolation, legitimate-controller coupling, analytics read-only, and Phase 9 behavior scans: no matches
- Post-E2E integration confirmed no residual fixtures
- No test was skipped

## Phase 7 result on 2026-09-30

- Phase 7 static/boundary checks: 25 passed, 0 failed
- Phase 7 database integration: 14 passed, 0 failed
- Phase 7 disabled/enabled HTTP E2E and remediation retest: 22 passed, 0 failed
- Existing full HTTP/E2E regression: 99 passed, 0 failed
- Phase 1 regression: 22 passed, 0 failed
- Phase 2 regression: 26 passed, 0 failed
- Development database verifier: 21 passed, 0 failed
- Integration preflight: 7 passed, 0 failed; ownership/activity: 8 passed, 0 failed
- Phase 3 regression: 17 passed, 0 failed
- Phase 4 regression: 15 passed, 0 failed
- Phase 5 regression: 20 passed, 0 failed
- Phase 5 database integration: 11 passed, 0 failed
- Phase 6 regression: 24 passed, 0 failed
- Phase 6 database integration: 13 passed, 0 failed
- PHP lint: 113 files passed, 0 failed
- Dangerous execution primitive scan: no matches
- Lab real-data and I/O reference scan: no matches
- Legitimate-controller lab-coupling scan: no matches
- Phase 8 active-behavior scan: no matches
- Post-E2E integration rerun found no residual telemetry, deception, or lab fixtures
- No test was skipped
