# Gate H Production Validation Record

## Current checkpoint

- **H-01 through H-20: PASS**
- **Gate H progress: 20/20 (100%) — CLOSED**
- Deployment mode remains `NORMAL_SAFE`; the controlled vulnerability lab remains disabled.
- Next state: **PRE-PENTEST BASELINE READY FOR FREEZE REVIEW**.

This record combines completed local regression evidence with sanitized production observations supplied by the operator. No production connection, deployment, database mutation, or external request was performed while recording this closure.

## H13 production patch

The operator created a local, non-webroot rollback package containing the eight previous production files, confirmed that each backup was non-empty, and replaced exactly these runtime files under `/htdocs`:

- `app/Services/SecurityEventService.php`
- `app/Models/SecurityEvent.php`
- `app/Models/Deception.php`
- `app/Controllers/SecurityController.php`
- `app/Controllers/SecurityApiController.php`
- `resources/views/security/index.php`
- `resources/views/security/show.php`
- `resources/views/security/deception.php`

`app/Helpers/functions.php` was not uploaded because production already contained the verified Gate F `$_ENV`-first environment compatibility fix. No environment, schema, seed, test, documentation, storage, credential, diagnostic, or lab-configuration file was uploaded. No production database mutation was part of deployment.

## Production sanity evidence

Operator-observed, read-only sanity checks passed 5/5:

| Check | Result |
|---|---|
| `/` | PASS — styled CHIMERA homepage; no visible warning, trace, debug output, or HTTP 500 |
| `/about` | PASS — normal styled page |
| `/assets/css/app.css` | PASS — stylesheet served |
| `/assets/js/app.js` | PASS — JavaScript served |
| `/lab/sqli` | PASS — normal CHIMERA 404; controlled lab remained disabled |

The Security Admin telemetry overview rendered successfully. It showed 41 total events, one authentication failure, 22 authorization denials, and zero high/critical events. The corrected production wording states that normalized events use deterministic threat scoring and that automated blocking/account action is not performed. Neither a raw source address nor an internal safe source identifier was visibly presented.

## H13-F01 — raw source persistence and presentation

**Finding:** Direct-peer source data had been persisted under the legacy `metadata_json.source_ip` key and could reach telemetry presentation paths.

**Remediation:**

- `REMOTE_ADDR` remains only the transient direct-peer input used to derive the existing HMAC-based correlation identifier.
- Forwarded/proxy-controlled source headers remain ignored.
- New event metadata rejects and does not persist the legacy raw-source key.
- Event and deception presentation models strip the legacy key defensively.
- Raw-source filtering and UI presentation were removed.
- Telemetry and deception output do not substitute the internal correlation identifier for the removed raw value.
- Database schema, scoring weights, classifications, thresholds, contributors, and session-correlation boundaries were unchanged.

**Production writer evidence:** Before deployment, 39 of 39 events contained the legacy key. After deployment and normal validation activity, production contained 41 events: the same 39 historical rows contained the key and two new rows did not. Only aggregate counts were inspected; no source value or internal identifier was selected or displayed.

**Production presentation evidence:** The authenticated Security API returned successfully. Browser text searches found no raw-source key and no internal safe-identifier field, including for legacy rows. The telemetry overview/event listing likewise presented neither value.

**Final status: PASS.**

## H13-F02 — telemetry wording

**Finding:** The previous overview text incorrectly implied that scoring was inactive.

**Remediation:** Production now accurately states that deterministic threat scoring is active while automated blocking and account action are not performed. It does not claim autonomous or AI response behavior.

**Final status: PASS.**

## Historical data decision

Exactly 39 historical `security_events` rows retain the legacy metadata key. They were not deleted, rewritten, or sanitized in storage. The current application prevents new persistence and strips legacy data before UI/API presentation.

Historical cleanup is not authorized by this checkpoint. Any cleanup requires a separate migration/retention decision, backup and rollback planning, exact aggregate verification, and explicit operator authorization after the application privacy boundary is established.

## Local regression evidence

The approved local remediation regression completed before deployment:

- 584 passed, 0 failed, 0 skipped
- HTTP/E2E: 100 passed
- H13 privacy assertions: 12 passed
- PHP lint: 145/145 passed
- Repository secret, dangerous primitive, route/security, error-disclosure, LAB-isolation, analytics read-only, InfinityFree artifact-leakage, and H13 UI/API exposure checks: PASS
- Test-database cleanup: PASS
- Schema changes: none
- Scoring/correlation changes: none
- Vulnerability-lab behavior changes: none

## Closure

H-13 is closed as **PASS** based on the complete local regression plus the operator-supplied production writer, presentation, sanity, and lab-disabled evidence.

**Gate H at H-13 closure = 13/20 (65%).**

## H-14 threat-scoring sanity closure

H-14 threat-scoring sanity was validated locally and then verified against production through three operator-executed, read-only aggregate queries. No individual event, source address, safe source identifier, credential, cookie, token, or private metadata value was retrieved.

Focused tests added:

- `tests/h14_scoring.php`
- `tests/h14_scoring_integration.php`

Verified locally:

- the positive scoring rule set contains exactly the ten approved rules and weights;
- every other current taxonomy event resolves to zero weight;
- score bounding at -1, 0, 19, 20, 44, 45, 74, 75, 100, 101, and 10000;
- LOW, MEDIUM, HIGH, and CRITICAL boundary behavior, including bounded out-of-range classification;
- absence of account, role, document, authorization, vulnerability-state, blocking, suspension, or response mutation from the scoring service;
- event, contributor, persisted score, and classification consistency for every positive rule;
- zero-weight correlation without a positive contributor;
- deterministic accumulation of separate identical legitimate events;
- idempotent replay of the same event row;
- first-only contribution for repeated access to the same decoy in one active session;
- full contributor evidence with persisted and reconstructed score saturation at 100;
- authenticated/anonymous and 30-minute session-window boundaries;
- contributor-label/event/session/rule/delta consistency;
- LAB events remain uncorrelated and zero-score;
- H13 privacy assertions remain passing;
- exact H14 fixtures are removed from `chimera_test`.

Direct transaction-failure injection was not exercised because doing so deterministically would require an invasive database trigger, schema change, or new application seam. Existing transaction start, rollback, row lock, unprocessed-event predicate, and concurrent-linkage row-count guards remain statically verified.

Results:

- focused H14 static: 37 passed, 0 failed, 0 skipped;
- focused H14 integration: 21 passed, 0 failed, 0 skipped;
- required H14/supporting regression: 311 passed, 0 failed, 0 skipped;
- complete Phase 1–10 plus H13/H14 regression: 642 passed, 0 failed, 0 skipped.

### Production read-only validation

The following sanitized results were supplied by the operator. No production query was executed while recording this closure.

**H14-P1 — contributor integrity: PASS**

- contributor rows: 23
- contributor-weight mismatches: 0
- invalid contributor rows: 0
- unattached contributors: 0
- contributor/event mismatches: 0

All production contributors use approved rules and weights and resolve consistently to their event and security session.

**H14-P2 — session reconstruction: PASS**

- total security sessions: 16
- invalid score ranges: 0
- reconstructed-score mismatches: 0
- stored-classification mismatches: 0
- reconstructed-classification mismatches: 0
- request-count mismatches: 0

All stored scores are within 0–100, equal the bounded contributor reconstruction, have the correct classification, and have request counts matching correlated events.

**H14-P3 — event, correlation, LAB, and privacy integrity: PASS**

- total security events: 41
- event-weight mismatches: 0
- zero-weight positive events: 0
- uncorrelated operational events: 0
- LAB correlation violations: 0
- malformed safe identifiers: 0
- historical rows retaining the legacy raw-source metadata key: 39

No source or identifier value was selected. The historical count remains exactly 39, demonstrating that H14 introduced no renewed raw-source persistence.

### Required H14 matrix

| Check | Requirement | Result | Evidence |
|---|---|---|---|
| H14.1 | Configured event weights | PASS | Exact local ten-rule set; P1/P3 mismatch counts zero |
| H14.2 | LOW boundary 0–19 | PASS | Local boundary and out-of-range tests |
| H14.3 | MEDIUM boundary 20–44 | PASS | Local boundary tests |
| H14.4 | HIGH boundary 45–74 | PASS | Local boundary tests |
| H14.5 | CRITICAL boundary 75–100 | PASS | Local boundary tests |
| H14.6 | Score bounded at 100 | PASS | Local saturation; P2 invalid range/reconstruction counts zero |
| H14.7 | Zero-weight behavior | PASS | Local zero-weight tests; P3 zero violations |
| H14.8 | Contributor weights | PASS | Local all-rule integration; P1 mismatches zero |
| H14.9 | Score reconstruction | PASS | Local saturation/reconstruction; P2 mismatches zero |
| H14.10 | Classification reconstruction | PASS | Local boundary tests; P2 classification mismatches zero |
| H14.11 | Event/session/contributor correlation | PASS | Local linkage tests; P1/P2/P3 integrity counts zero |
| H14.12 | Repeated legitimate accumulation | PASS | Local separate-event accumulation and same-event idempotency |
| H14.13 | No automated blocking/account action | PASS | Local dependency and mutation-boundary checks |
| H14.14 | Adaptive classification consumption without scoring mutation | PASS | Phase 6 static/integration regression |
| H14.15 | H13 privacy preservation | PASS | H13 privacy regression and unchanged 39-row legacy aggregate |

Repeated access to the same configured decoy in one active session remains the documented exception: the first matching access contributes 20 and subsequent matching access contributes zero. This is intentional feedback-loop suppression, not a mismatch.

### Historical privacy data

Exactly 39 historical `security_events` rows retain the legacy raw-source metadata key. They remain intentionally unchanged. Historical cleanup is not authorized by H14 and requires a separate retention/migration decision.

No application behavior, scoring rule, threshold, schema, production configuration, or production data was changed during closure.

**H-14 = PASS. Gate H = 14/20 (70%). H-15 is NOT STARTED.**

## H-15 deception and adaptive dashboards — final closure

H-15 is closed after focused local remediation, complete regression, deployment of the approved two-file production patch, operator-supplied read-only database evidence, and read-only Security Admin dashboard/API validation.

### H15-F01 — adaptive legacy-source presentation

`AdaptiveDeception::present()` decoded legacy event metadata without removing the historical `source_ip` key. Because the adaptive APIs serialize this common model output, a legacy adaptive event could expose that field even though the HTML templates did not render it.

The common presenter now removes both `metadata.source_ip` and `metadata.source_safe_identifier`, as well as defensive top-level occurrences, while preserving the safe adaptive profile, variant, reason, score, endpoint, and event fields used by the dashboards and APIs. No historical database row was modified.

### H15-G01 — honeytoken presentation minimization

`Honeytoken::recentEvents()` previously selected `security_events.source_safe_identifier` even though the deception dashboard did not use it. The query projection now omits that column, preventing unnecessary propagation into view scope.

### Focused and regression evidence

- H15 static/privacy: 31 passed, 0 failed, 0 skipped
- H15 integration/privacy: 16 passed, 0 failed, 0 skipped
- Focused H15 total: 47 passed, 0 failed, 0 skipped
- Requested Phase 4–8, H13, H14, and HTTP/E2E supporting suites: 351 passed, 0 failed, 0 skipped
- Complete canonical local regression, including H15: 689 passed, 0 failed, 0 skipped
- HTTP/E2E: 100 passed, 0 failed
- PHP lint: 149/149 passed
- Repository secret scan: PASS
- H15 dangerous-primitive and presentation-query scans: PASS
- Route/RBAC, production error-disclosure, LAB isolation, analytics read-only, InfinityFree artifact/security, H13 privacy, and H14 scoring checks: PASS through the executed canonical suites
- H15 integration fixture cleanup: PASS
- Schema, scoring rules, classification thresholds, adaptive profile policy, decoy configuration, honeytoken configuration, and LAB behavior: unchanged

H15-G02 remains a documented resilience observation rather than a confirmed defect: security-event/session correlation and honeytoken linkage use separate transactions. The normal path was verified to create exactly one linked honeytoken event. No invasive database failure was introduced.

### Operator-supplied production read-only evidence

The following read-only query results were supplied by the operator. They were not rerun while recording this closure.

**H15-P1 — PASS**

- total decoys: 3
- active decoys: 3
- expected decoys: 3
- unexpected decoys: 0
- total honeytokens: 2
- active honeytokens: 2
- expected honeytokens: 2
- unexpected honeytokens: 0
- malformed honeytoken hashes: 0

**H15-P2 — PASS**

- decoy events: 0
- honeytoken events: 0
- decoy weight/suppression mismatches: 0
- honeytoken weight mismatches: 0
- honeytoken link mismatches: 0
- invalid honeytoken links: 0
- adaptive nonzero deltas: 0
- invalid adaptive profiles: 0

The absence of intentional production decoy, honeytoken, and adaptive interaction evidence is accepted. No production interaction was generated merely to populate these counts.

**H15-P3 — PASS**

- active decoys: 3
- honeytokens: 2
- decoy interactions: 0
- honeytoken triggers: 0
- adaptive renders: 0
- profile transitions: 0
- assessed sessions: 0
- historical rows retaining the legacy raw-source metadata key: 39

The 39 historical rows remain intentionally untouched. Historical cleanup is not authorized.

### Production patch and post-patch validation

Before deployment, the operator retained a local rollback copy of the previous production versions. Only these runtime files were replaced:

- `/htdocs/app/Models/AdaptiveDeception.php`
- `/htdocs/app/Models/Honeytoken.php`

No schema, configuration, environment, database, historical telemetry, scoring policy, adaptive profile, account, role, document, or LAB state was changed by the patch.

Post-patch sanity passed for `/`, `/about`, the primary CSS and JavaScript assets, and the normal disabled-LAB 404 at `/lab/sqli`. No HTTP 500 or routing/static regression was observed.

The Security Admin deception dashboard matched P3: three active decoys, zero decoy interactions, two honeytokens, and zero token triggers. The adaptive dashboard showed zero renders, transitions, assessed sessions, and current-profile counts, with no recent decisions. This is expected because no production deception interaction was intentionally generated.

The read-only APIs passed:

- adaptive events returned an empty data set and count zero;
- adaptive summary returned zero sessions in every profile and empty interaction groups;
- deception summary matched P3;
- decoy inventory returned exactly the three configured synthetic decoys and no `/backup` decoy;
- honeytoken inventory returned exactly two active synthetic entries with no trigger timestamp, hash, runtime material, raw source, or safe-source field;
- deception events returned an empty data set and count zero.

No prohibited source or credential field was observed. The adaptive-session detail endpoint was not dynamically exercised because production has zero legitimate adaptive sessions. No event was manufactured for that purpose; the shared presenter used by that endpoint is covered by the focused local legacy-fixture regression.

### Final H15 validation matrix

| Check | Requirement | Current evidence/status |
|---|---|---|
| H15.1 | Configured decoys synthetic and represented correctly | PASS — local coverage, P1, inventory API |
| H15.2 | Intended decoy routing boundary | PASS — local routing/E2E and production inventory |
| H15.3 | `DECOY_ACCESSED` scoring | PASS — local H14/H15 evidence; production P2 has no interaction rows or mismatches |
| H15.4 | Same-decoy suppression | PASS — local integration; production P2 mismatch count zero with no interaction rows |
| H15.5 | Honeytoken storage/configuration safety | PASS — local privacy coverage, P1, minimized inventory API |
| H15.6 | `HONEYTOKEN_TRIGGERED` scoring | PASS — local H14/H15 evidence; production P2 has no interaction rows or mismatches |
| H15.7 | LOW profile | PASS — local deterministic policy and integration |
| H15.8 | MEDIUM profile | PASS — local deterministic policy and integration |
| H15.9 | HIGH profile | PASS — local deterministic policy and integration |
| H15.10 | CRITICAL profile | PASS — local deterministic policy and integration |
| H15.11 | Deterministic safe fallback | PASS — local static/integration evidence |
| H15.12 | Classification consumed without scoring mutation | PASS — local evidence and production P2 |
| H15.13 | Dashboard authorization | PASS — route/RBAC regression and authenticated production dashboards |
| H15.14 | API authorization | PASS — route/RBAC regression and authenticated production APIs |
| H15.15 | Aggregate accuracy | PASS — local fixtures plus production P3/dashboard/API agreement |
| H15.16 | No raw source or sensitive marker exposure | PASS — local legacy-fixture regression and patched-production API evidence |
| H15.17 | No legitimate-data or authorization mutation | PASS — local before/after invariants and patch scope |
| H15.18 | No dangerous execution/persistence | PASS — static/security scans |
| H15.19 | LAB isolated and disabled by default | PASS — local regression and post-patch production 404 |
| H15.20 | H13 privacy and H14 scoring preserved | PASS — complete regression and post-patch evidence |

H15-F01 is remediated and verified locally and in the patched production presentation paths. H15-G01 is remediated by query minimization. H15-G02 remains a documented resilience observation, not a confirmed production defect: normal linkage consistency passed locally and no invasive transaction-failure injection was performed.

Exactly 39 historical rows retain the legacy raw-source metadata key and remain intentionally untouched. No production decoy or honeytoken route was intentionally triggered for H15.

**H-15 = PASS. Gate H = 15/20 (75%). H-16 is NOT STARTED.**

## H-16 analytics and evidence export — local remediation checkpoint

The H16 audit found five blocking implementation mismatches:

- H16-F01: analytics session models, HTML, APIs, and `session_evidence` exports presented the internal source-correlation hash under `source_identifier`;
- H16-F02: malformed filters were cleared and could broaden a dashboard/API/export query;
- H16-F03: a one-sided date could bypass the 366-day range bound;
- H16-F04: export types silently ignored filters outside their actual data semantics;
- H16-F05: event exports were unintentionally clamped to 200 while documented as 1,000, and the LAB module export query lacked an explicit row limit.

The local remediation removes the internal source field from analytics query projections and all presentation/export models, makes invalid filters return no browser data or API/export `422 INVALID_FILTER`, requires paired date endpoints within 366 days, defines and enforces per-export filter contracts, separates export `type` from the optional `event_type` filter, preserves applicable dashboard filters in export links, and applies explicit 1,000-row bounds to every export type. Stable evidence IDs remain available. There was no schema, scoring, classification, adaptive/deception, role, document, account, or LAB-policy change.

### Local validation evidence

- H16 static/privacy: 40 passed, 0 failed, 0 skipped
- H16 integration/privacy: 22 passed, 0 failed, 0 skipped
- Focused H16 total: 62 passed, 0 failed, 0 skipped
- Phase 8 HTTP/E2E: 25 passed, 0 failed, including the exact generic `session_evidence` URL
- Full canonical regression: 751 passed, 0 failed, 0 skipped
- PHP lint: 151/151 passed
- Security/static/privacy scans: PASS
- `chimera_test` fixture cleanup: PASS

### Operator-supplied pre-patch production baselines

H16-P1 grouped counts were visually reconfirmed in phpMyAdmin:

- categories: AUTHENTICATION 18, AUTHORIZATION 25, REQUEST_SECURITY 2;
- classifications: LOW 17, MEDIUM 3;
- event types: ACCESS_DENIED 19, CSRF_REJECTED 1, INVALID_REQUEST 1, LOGIN_FAILURE 1, LOGIN_SUCCESS 6, LOGOUT 7, REGISTRATION_SUCCESS 4, ROLE_ACCESS_DENIED 6;
- severities: INFO 17, LOW 20, MEDIUM 8.

H16-P2 returned 45 events, 20 sessions, 26 contributors, zero decoy events, zero honeytoken events, zero adaptive events, zero LAB events, and 39 historical rows retaining the legacy raw-source metadata key.

These are pre-patch read-only baselines. They were not rerun during local remediation. Production was not accessed or modified. The 39 historical rows remain intentionally retained and were not cleaned.

**H-16 = LOCAL REMEDIATION PASSED — PRODUCTION PATCH PENDING. Gate H remains 15/20 (75%). H-17 is NOT STARTED.**

### H16-F06 — generic session-evidence export contract

After the initial H16 runtime patch, the operator confirmed that the dashboard and summary API matched the 45-event/20-session baseline and exposed no prohibited source field. The dashboard-generated request `/api/security/analytics/export?type=session_evidence&format=json` nevertheless returned `422 INVALID_EXPORT`.

Local reproduction proved a UI/backend contract mismatch. `session_evidence` was allowlisted and correctly routed, but `SecurityAnalyticsService::exportRows()` cast the omitted `session_id` to zero, `sessionAnalysis(0)` returned no resource, and the export controller converted that result into `INVALID_EXPORT`. Existing tests covered only the explicit `session_id` form.

The local H16-F06 correction makes the exact generic dashboard request select exactly one deterministic latest session using `last_seen_at DESC, id DESC LIMIT 1`; an empty database produces an empty export array. Explicit positive session IDs remain supported. Malformed IDs, unsupported export types, invalid filters, and filters incompatible with `session_evidence` still return safe 422 responses. The result remains read-only and inherits the existing 500-event/contributor session-detail bounds, source-field removal, safe metadata projection, and JSON/CSV serialization.

Before correction, the exact local Security Admin request reproduced `INVALID_EXPORT`. After correction it returned HTTP 200 JSON; guest returned 401, USER and ADMIN returned 403, unsupported types returned `INVALID_EXPORT`, incompatible filters returned `INVALID_FILTER`, and source/correlation/credential/session-secret checks passed. No schema, production database, production configuration, score, role, document, deception/adaptive, or LAB state was changed.

**H-16 = REMEDIATION/VALIDATION PENDING. Gate H remains 15/20 (75%). H-17 is NOT STARTED.**

### H16 final production closure

The operator retained a current-production pre-F06 rollback backup and replaced only:

- `/htdocs/app/Services/SecurityAnalyticsService.php`
- `/htdocs/app/Controllers/SecurityAnalyticsApiController.php`

Post-patch production sanity passed for `/`, `/about`, and the authenticated `/security/analytics` dashboard. `/lab/sqli` continued to return the normal CHIMERA 404, the vulnerability LAB remained disabled, and no HTTP 500 was observed.

The exact previously failing Security Admin request was repeated:

`GET /api/security/analytics/export?type=session_evidence&format=json`

It returned a successful JSON `session_evidence` export generated at `2026-10-06T08:15:50+00:00` containing exactly one existing session record. The bounded record reported evidence ID `SEC-00000021`, score 3, classification LOW, one request, one contributor, reconstructed score 3, and integrity status CONSISTENT. Its timeline contained one LOW `ACCESS_DENIED` event (`EVT-00000046`) for `GET /security/lab`, with a 3-point contributor and safe metadata limited to category AUTHORIZATION and outcome DENIED. Detection latency was zero; deception and honeytoken evidence were absent.

The `/security/lab` entry records unauthenticated authorization denial only. It does not indicate controlled-LAB execution or vulnerability-module activation.

The response contained no `source_ip`, `source_safe_identifier`, `source_identifier`, `source_hash`, password, authentication token, cookie, CSRF token, or session-secret material. It produced no HTTP 500 or `INVALID_EXPORT`, remained read-only, and exposed only stable evidence identifiers and minimized evidence fields.

| Finding | Final disposition |
|---|---|
| H16-F01 | PASS — raw/internal source correlation removed from analytics UI, APIs, JSON, and CSV presentation |
| H16-F02 | PASS — invalid filters fail closed |
| H16-F03 | PASS — paired maximum-366-day date range enforced |
| H16-F04 | PASS — export-specific filter contracts enforced |
| H16-F05 | PASS — documented export bounds and LAB module bound enforced |
| H16-F06 | PASS — generic dashboard `session_evidence` contract remediated and production-validated |

H13 privacy remains preserved, including defensive presentation sanitization for the 39 intentionally retained historical raw-source-key rows. H14 scoring rules, thresholds, reconstruction and 0–100 bounds remain unchanged. H15 deception/adaptive profiles, score behavior, synthetic-data boundaries and LAB isolation remain unchanged. No schema or historical-data cleanup was performed, and no further production action is required for H16.

**H-16 = PASS. Gate H = 16/20 (80%). H-17 is NOT STARTED.**

## H-17 CSRF negative control — local remediation checkpoint

H17-F01 was remediated locally in `app/Middleware/VerifyCsrf.php`. The middleware no longer casts arbitrary `_token` input to string: it requires a submitted string before invoking the existing constant-time CSRF validator. Missing, invalid, malformed, array-valued, and stale tokens fail safely with the existing HTTP 419 path. The rejection still records `CSRF_REJECTED`, retains the locked +12 contribution, and terminates before controller/business mutation.

Three focused suites were added:

- `tests/h17_csrf.php`: authoritative seven-route inventory, middleware/form placement, token construction/comparison, taxonomy, score, privacy, response, and default-disabled LAB assertions;
- `tests/h17_csrf_integration.php`: exact event/session/contributor correlation, deterministic repeated accumulation, same-event idempotency, analytics/evidence privacy, and exact database cleanup against guarded `chimera_test`;
- `tests/h17_csrf_http_e2e.php`: all seven POST mutation routes, missing/invalid/malformed/array/stale token behavior, protected-state snapshots, authentication/RBAC precedence, valid workflows, privacy sentinel checks, LAB-disabled behavior, and exact database/private-file cleanup.

Local evidence on 2026-10-06:

- focused H17: 73 passed, 0 failed, 0 skipped (32 static + 12 integration + 29 HTTP/E2E);
- supporting established regression: 751 passed, 0 failed, 0 skipped;
- complete canonical regression including H17: 824 passed, 0 failed, 0 skipped;
- PHP lint: 154/154 passed;
- repository secret and established security/static/privacy checks: PASS;
- H17 fixture cleanup: PASS;
- schema/configuration/route/scoring/role/deception/analytics changes: NONE;
- production access or mutation: NONE.

The malformed array request returned 419 without an array-to-string warning, stack trace, filesystem path, or HTTP 500. Rejected registration/login/logout/profile/upload/delete/LAB-state requests left their protected state unchanged. Eight deliberate HTTP CSRF rejections produced exactly eight events and eight matching +12 contributors. Valid CSRF workflows remained functional. H13 privacy, H14 scoring, H15 deception/adaptive, H16 analytics/export, and default-disabled LAB invariants remained preserved.

The previously accepted H-08 production evidence proves the missing-CSRF logout rejection path, exact 419 behavior, preserved authentication, and matching production telemetry. No new production CSRF-negative request was required.

### Production deployment and final closure

The operator retained a rollback copy of the previous production middleware and replaced only `/htdocs/app/Middleware/VerifyCsrf.php` with the locally validated correction. Post-deployment production sanity passed for `/`, `/about`, and `/login`; no HTTP 500, PHP warning, or blank page was observed.

The operator then performed one legitimate positive CSRF control through the authenticated Security Admin Profile UI. `POST /profile` succeeded normally and displayed `Your profile was updated.` The Security Admin remained authenticated, and the valid request produced no HTTP 419, HTTP 500, or warning. No new production negative-CSRF request was sent.

The deployed positive-control evidence, accepted H-08 negative-control evidence, and 824-check local canonical regression establish both valid and rejected production CSRF behavior without duplicating scored negative telemetry. H13 privacy, H14 scoring, H15 deception/adaptive, H16 analytics/export, RBAC, LAB isolation/default-disabled behavior, and the unchanged schema/configuration/routes remain preserved.

**H-17 = PASS. Gate H = 17/20 (85%). H-18 is NOT STARTED.**

## H-18 local validation checkpoint — two-user document ownership

The accepted audit found no H18-Fxx application defect. Three dedicated suites were added without changing runtime code:

- `tests/h18_document_ownership.php` locks the seven document routes, authentication and CSRF contracts, SQL owner predicates, pre-storage authorization, defense-in-depth delete predicate, safe 404 behavior, private-storage controls, exact +12 score, API minimization, and LAB separation;
- `tests/h18_document_ownership_integration.php` uses guarded `chimera_test` fixtures to verify owner-scoped lookup/listing, failed foreign-user deletion rollback and file restoration, four exact event/contributor relationships, 48/HIGH reconstruction, privacy, zero document mutation, and cleanup;
- `tests/h18_document_ownership_http_e2e.php` performs the authoritative two-user upload/list/detail/download/deny/recheck/delete workflow through real local HTTP sessions.

Results on 2026-10-07:

- focused H18: 74 passed, 0 failed, 0 skipped (34 static + 8 integration + 32 HTTP/E2E);
- supporting established suites: 824 passed, 0 failed, 0 skipped;
- canonical aggregate including H18: 898 passed, 0 failed, 0 skipped;
- PHP lint: 157/157 passed;
- established security/static/privacy/invariant checks: PASS;
- database, active-file, and trash fixture cleanup: PASS.

USER B's primary HTML-detail, download, API-detail, and valid-CSRF delete requests created exactly four `OWNERSHIP_ACCESS_DENIED` events and four +12 contributors, producing score 48/HIGH. No protected document/activity/LAB mutation occurred. Cross-owner and nonexistent positive numeric IDs had equivalent safe response semantics. USER A retained byte-identical access and completed a legitimate valid-CSRF deletion with no new ownership denial and no residual trash file.

H13 source privacy, H14 scoring, H15 deception/adaptive isolation, H16 read-only bounded analytics/exports, H17 CSRF behavior, and LAB default-disabled isolation remain preserved. No decoy, honeytoken, or LAB interaction was generated.

H18-G01–G03 are satisfied locally. H18-G04 remains assigned to H19 because application ownership testing does not prove provider-level direct-storage denial. H18-G05 rollback restoration and normal trash cleanup passed; post-commit unlink-failure injection remains a non-blocking resilience observation. No application runtime, schema, configuration, or route change was made, and production was not accessed.

Production validation remains required and separately gated. The recommended next step is provisioning exactly one dedicated USER B while retaining the H11 USER as USER A; no production action is authorized by this checkpoint.

**H-18 = LOCAL VALIDATION COMPLETE / PRODUCTION PENDING. Gate H remains 17/20 (85%). H-19 and H-20 are NOT STARTED.**

### H-18 production evidence and final closure

The operator completed production validation without a runtime patch or SQL operation. The retained H11 USER served as USER A, and exactly one dedicated USER B was registered normally with role `user`. USER B logout/session invalidation passed. No privileged account was used as an ownership-test actor.

USER A's harmless 94-byte text document passed production listing, details, download, and byte-integrity controls. USER B could not see it in the owner-scoped listing. Cross-owner detail and download each returned HTTP 404 without metadata or content disclosure. One corrected deletion request using USER B authentication, POST, and a valid USER B CSRF token also returned the generic HTTP 404 and did not delete the foreign document. A preceding malformed request returned HTTP 405, produced no ownership event, and is excluded from ownership evidence.

USER A's post-denial control confirmed the document, metadata, size, integrity information, download access, and exact content remained intact. USER A then deleted the document through the legitimate owner workflow. The temporary USER B document used to obtain the standard deletion form was also deleted normally; no H18 test document intentionally remains.

Production telemetry contained exactly:

| Event | Endpoint | Method | Points |
|---|---|---|---:|
| `OWNERSHIP_ACCESS_DENIED` | `/documents/1` | GET | 12 |
| `OWNERSHIP_ACCESS_DENIED` | `/documents/1/download` | GET | 12 |
| `OWNERSHIP_ACCESS_DENIED` | `/documents/1/delete` | POST | 12 |

The aggregate was exactly 3 events / 36 points, consistent with MEDIUM classification. Production analytics showed no HIGH/CRITICAL session, deception interaction, honeytoken interaction, or controlled-LAB activity. Legitimate owner deletion appeared separately as `DOCUMENT_DELETE`, category `DOCUMENT_SECURITY`, severity `INFO`, outcome `SUCCESS`.

H18-G01–G03 are satisfied. H18-G04 remains intentionally deferred to H19's provider-level direct-storage validation and does not block H18. H18-G05 remains a non-blocking resilience observation. H13–H17 invariants remain preserved, and application runtime code, schema, configuration, and routes remain unchanged.

**H-18 = PASS. Gate H = 18/20 (90%). H-19 and H-20 are NOT STARTED.**

## H-19 local validation checkpoint — storage denial after workflow

No H19-Fxx application defect was identified. Three dedicated local suites were added without changing application runtime behavior:

- `tests/h19_storage_denial.php` validates root/storage Apache policy semantics and ordering, directory-index and executable controls, protected topology, manifest coverage, fail-closed readiness attestation, route/public/sensitive-file isolation, locked scoring, and default-disabled LAB state;
- `tests/h19_storage_denial_integration.php` validates guarded `chimera_test` private-root confinement, generated-name safety, invalid-name/configuration rejection, content and checksum integrity, optional symlink rejection, trash confinement, rollback restoration, normal deletion, zero positive scoring, LAB immutability, and exact cleanup;
- `tests/h19_storage_denial_http_e2e.php` validates the owner upload/list/detail/download/delete workflow, byte integrity, presentation minimization, one local direct-path non-disclosure request, zero telemetry from that local 404, zero-weight owner telemetry, no deception/honeytoken/LAB interaction, and cleanup.

Results on 2026-10-07:

- focused H19: 66 passed, 0 failed, 1 skipped (34 static + 16 integration + 16 HTTP/E2E);
- supporting established suites: 898 passed, 0 failed, 0 skipped;
- canonical aggregate including H19: 964 passed, 0 failed, 1 skipped;
- PHP lint: 160/160 passed;
- established secret/security/static/privacy/invariant checks: PASS;
- H19 database, active-file, symlink, and trash fixture cleanup: PASS; `chimera_test` remained the expected 11-table schema.

The one justified skip records unavailable Windows symlink creation under the current privilege/filesystem policy; it does not suppress a failing application assertion. The local direct request returned a safe CHIMERA 404 without private sentinel, physical path, stack trace, warning, credential, session, CSRF, or source-correlation disclosure. Because the harness is PHP's development server with CHIMERA routing, this result does not prove InfinityFree Apache `.htaccess` enforcement.

H19-G01 provider enforcement, H19-G02 local Apache fidelity, H19-G03 scoped production target discovery, and H19-G06 live attestation remain open until the separately authorized production workflow. H19-G04 inherited storage denial passed static review but remains provider-dependent. H19-G05 controls passed without establishing a defect or need for runtime hardening. H19-G07 normal cleanup and rollback passed; invasive unlink-failure injection remains a non-blocking resilience observation.

H13 source privacy, H14 deterministic scoring, H15 deception/adaptive isolation, H16 read-only bounded analytics/exports, H17 CSRF, H18 ownership, and LAB default-disabled isolation remain preserved. No schema, configuration, route, root/storage policy, or runtime application file changed, and production was not accessed.

Next gate: separately authorize one minimal provider-boundary validation using one retained USER and harmless text document, one scoped read-only `storage_name` lookup, one exact direct-file request, at most one exact directory request, owner integrity recheck, and legitimate cleanup. H19 cannot close from local evidence alone.

**H-19 = LOCAL VALIDATION COMPLETE / PRODUCTION PENDING. Gate H remains 18/20 (90%). H-20 is NOT STARTED.**

### H-19 production evidence and final closure

The operator completed the approved minimal production workflow without a runtime patch, configuration change, or mutation SQL. The retained H11 standard USER uploaded one harmless temporary text fixture (document ID 3). Owner listing, details, application download, and content integrity passed before boundary testing.

One scoped read-only lookup selected only the known fixture's ID, original name, and internal storage name and returned exactly one row. The internal name remains private and is intentionally absent from this record. It was used solely to issue one exact, non-guessed request to the known-existing physical file.

The direct private-file request returned the generic InfinityFree provider HTTP 403 response. It was neither a CHIMERA page nor a CHIMERA 404, proving that the deployed provider/web-server boundary rejected the known-existing file before application routing. The private sentinel and file body were not returned. No filesystem path, directory information, warning, stack trace, application detail, credential, session, CSRF value, or internal source identifier was disclosed.

One additional exact request to `/storage/uploads/documents/` returned the same provider-level HTTP 403 with no directory index, filenames, generated names, timestamps, metadata, redirect, or sensitive disclosure. No path enumeration, scanning, fuzzing, case/encoding mutation, recursive request, or executable fixture was used.

The post-denial owner control confirmed normal application access and unchanged fixture content. The owner then deleted the fixture through CHIMERA, and it disappeared from the document listing. No SQL, File Manager, or direct-storage cleanup was used.

The provider 403 occurs before `public/index.php`; therefore zero CHIMERA events, contributors, and score increase is the correct expected result for each direct denial. No application telemetry is required to substantiate this web-server boundary. Normal owner document events remain zero-weight, and no deception, honeytoken, or LAB activity was introduced.

Final observation disposition:

- H19-G01: CLOSED — provider enforcement proved against a known-existing private file and storage directory.
- H19-G02: non-blocking documented limitation superseded for closure by live provider evidence.
- H19-G03: CLOSED — one scoped read-only target lookup completed without enumeration.
- H19-G04: non-blocking defense-in-depth observation; inherited denial passed locally and the deployed subtree returned provider 403.
- H19-G05: non-blocking optional hardening; no MultiViews or handler bypass was demonstrated.
- H19-G06: SATISFIED — live operator evidence establishes known-file and directory denial on the final deployed topology.
- H19-G07: non-blocking resilience observation; normal cleanup and rollback passed, while invasive unlink-failure injection was not performed.

Combined local and production evidence establishes path confinement, generated-name isolation, traversal/malformed-name rejection, direct known-file denial, directory-listing denial, private-content non-disclosure, web-server rejection before CHIMERA routing, preserved owner access/integrity, legitimate deletion, executable-upload controls, and a bounded non-enumerative validation process. H13–H18 and LAB isolation remain preserved.

No H19-Fxx defect or closure blocker remains. Runtime application code, schema, configuration, routes, root `.htaccess`, and storage `.htaccess` were unchanged. No production patch is required.

**H-19 = PASS. Gate H = 19/20 (95%). H-20 is NOT STARTED.**

## H-20 final Gate H assurance review and closure

H20 performed no production request, database operation, deployment, probing, scanning, LAB activation, deception trigger, honeytoken trigger, or runtime remediation. It reconciled the accepted operator evidence with the current repository and reran every existing local suite through H19.

For H01–H12, the repository does not retain separate original checkpoint-title sections. The following matrix therefore records their consolidated assurance purpose from the accepted operator checkpoints and current regression, without inventing additional production evidence. H13–H19 retain their dedicated closure records above.

| Checkpoint | Consolidated purpose | Accepted/current evidence | Status | Residual observation | Still valid? |
|---|---|---|---|---|---|
| H-01 | Deployment readiness and target identity | Phase 9/10 readiness, protected topology, accepted production baseline | PASS | Operator/provider evidence model | YES |
| H-02 | Public boot, routing, and static assets | Production sanity records; local HTTP and routing regression | PASS | None | YES |
| H-03 | Runtime database and 11-table schema | Database verifier, guarded integration, production baseline evidence | PASS | No H13–H20 schema migration | YES |
| H-04 | Registration and account creation | Main HTTP/E2E; later H18 production USER registration | PASS | Synthetic standard accounts retained | YES |
| H-05 | Login and authenticated-session establishment | Main HTTP/E2E; H17/H18 production controls | PASS | None | YES |
| H-06 | Logout and protected-route invalidation | Main HTTP/E2E; H18 production logout observation | PASS | None | YES |
| H-07 | Role isolation and protected application access | Route/RBAC suites and multi-role HTTP/E2E | PASS | None | YES |
| H-08 | CSRF negative control | Accepted production HTTP 419 evidence; H17 focused regression | PASS | No duplicate production negative test required | YES |
| H-09 | Normal document workflow and private application download | Phase 2, main HTTP/E2E, H18/H19 owner controls | PASS | Provider boundary handled separately by H19 | YES |
| H-10 | NORMAL_SAFE and default-disabled LAB operation | Phase 7/9/10 plus production 404 sanity evidence | PASS | LAB activation remains separately authorized | YES |
| H-11 | Dedicated standard-USER production workflow | Accepted retained H11 USER; reused successfully in H18/H19 | PASS | Retained synthetic standard account | YES |
| H-12 | Security Admin operational authorization | Security dashboard/API and exact-role regression; accepted production access | PASS | None | YES |
| H-13 | Telemetry persistence and privacy | Writer/API/UI production evidence; H13 regression | PASS | 39 historical raw-source-key rows retained and sanitized | YES |
| H-14 | Deterministic threat-scoring sanity | 58 focused local checks; production P1/P2/P3 aggregates | PASS | Dynamic transaction fault injection not introduced | YES |
| H-15 | Deception and adaptive dashboards | 47 focused checks; two-file privacy patch; production dashboard/API evidence | PASS | Honeytoken linkage uses a separate transaction | YES |
| H-16 | Read-only analytics and bounded evidence export | 62 focused checks; F01–F06 fixes; exact production export validation | PASS | None | YES |
| H-17 | CSRF negative control and malformed-token safety | 73 focused checks; middleware deployment; positive and accepted negative controls | PASS | None | YES |
| H-18 | Two-user document ownership | 74 focused checks; three production denials and 36 points | PASS | Post-commit unlink-failure injection not performed | YES |
| H-19 | Provider/private-storage boundary | 66 focused checks; known-file and directory provider HTTP 403 evidence | PASS | One optional symlink skip; provider/local-fidelity observations | YES |
| H-20 | Final assurance, drift, and freeze-readiness review | 964-check canonical regression, lint, scans, evidence reconciliation | PASS | Residual observations classified below | YES |

### Final local verification

- complete canonical regression through H19: **964 passed, 0 failed, 1 skipped**;
- PHP lint: **160/160 passed**;
- independent repository secret scan: **0 findings**;
- database/fixture cleanup verification: PASS, with the expected 11-table `chimera_test` schema intact;
- dangerous-primitive, route/RBAC, error-disclosure, analytics-read-only, LAB-isolation/default-disabled, deployment-artifact, H13 privacy, H14 scoring, H15 deception/privacy, H16 analytics/export, H17 CSRF, H18 ownership, and H19 storage-policy checks: PASS.

The single skip is the already documented optional Windows symlink-creation exercise. Local privilege/filesystem policy prevented fixture creation; internal-name validation, symlink rejection code, private storage policy, and live provider known-file denial remain independently covered. It is a non-blocking test-environment limitation.

### Final baseline findings

- Deployment: the `/htdocs` protected-in-webroot topology, root private-path denial, direct-`public/` denial, allowlisted asset mapping, sensitive/dotfile denial, storage policies, index denial, safe routing, and manifest exclusions remain repository-proven. Accepted operator evidence supplies production boot, asset, LAB-off, deployment, API, and provider-403 observations.
- Database: schema remains 11 tables. The reference seed contains only three synthetic decoys, two derived synthetic honeytokens, and three REMEDIATED vulnerability modules; it inserts no identities, documents, activity, telemetry, sessions, or credentials.
- Authentication/RBAC: registration, login, logout, session regeneration/invalidation, exact USER/ADMIN/Security Admin separation, and safe denials remain passing. All seven state-changing POST routes retain server-side CSRF middleware.
- Ownership/storage: H18 application authorization and H19 web-server storage denial prove distinct, complementary boundaries. Owner workflow, wrong-owner generic 404 behavior, zero unauthorized mutation, exact +12 ownership scoring, private-name confinement, direct-file provider 403, directory provider 403, and owner cleanup remain valid.
- Privacy/telemetry: new events do not persist raw source metadata; UI/API/analytics/export boundaries suppress raw and internal correlation fields. The 39 historical legacy rows remain intentionally stored but defensively sanitized.
- Scoring: the exact ten-rule weights, 0–100 bound, LOW/MEDIUM/HIGH/CRITICAL thresholds, idempotency, reconstruction, same-decoy suppression, zero-weight legitimate/adaptive/LAB behavior, and H18's 3 × 12 = 36/MEDIUM result remain consistent.
- Deception/LAB: configured decoys remain `/admin-old`, `/internal`, and `/api/debug`; honeytokens remain synthetic and minimized; profiles consume classification without changing scoring. LAB modules remain synthetic, REMEDIATED by reference baseline, gated, zero-score, and disabled by default.
- Analytics/export: H16-F01 through H16-F06 remain fixed; queries are read-only, filters fail closed, timelines/exports are bounded, CSV cells are neutralized, and the generic `session_evidence` contract remains supported.
- Error/secret/artifact hygiene: generic 404/419/production-error handling, provider 403 separation, warning/trace/path suppression, zero high-confidence secret findings, and manifest exclusion of environment, database, tests, documentation, repository/editor, logs, sessions, diagnostic, and temporary artifacts remain passing.

### Residual observation classification

| Observation | Classification | Security impact and disposition |
|---|---|---|
| 39 historical rows retain the legacy raw-source metadata key | ACCEPTED RISK | Presentation is defensively sanitized and new writes omit it; cleanup remains a separate retention decision. |
| Local PHP server cannot reproduce InfinityFree Apache enforcement | PROVIDER LIMITATION | Non-blocking because the known-existing production file and directory returned provider-level 403. |
| Optional Windows symlink fixture could not be created | TEST ENVIRONMENT LIMITATION | Non-blocking; no assertion was weakened and equivalent controls plus production denial are covered. |
| `documents/.trash` relies on inherited root/storage denial | ACCEPTED RISK | Static policy and deployed subtree denial are effective; no exposure was demonstrated. |
| MultiViews/handler suppression could be more explicit | FUTURE HARDENING | Total storage denial and executable/name allowlists are effective; no bypass exists in evidence. |
| Post-commit trash unlink failure was not invasively injected | RESILIENCE OBSERVATION | Rollback and ordinary cleanup pass; it does not undermine confidentiality or authorization evidence. |
| Honeytoken linkage follows the security-event transaction | RESILIENCE OBSERVATION | Normal linkage is consistent; no production defect was established. |
| Live webroot readiness uses operator attestation | PROVIDER LIMITATION | Satisfied for this baseline by bounded live provider evidence; no automated external probe is appropriate here. |
| Retained synthetic standard USER accounts | ACCEPTED RISK | They remain non-privileged controlled test identities; later retention is an explicit operational decision. |

No H20-Fxx blocker was found. H18 and H19 added only tests/documentation; H20 changes only closure documentation. Current sources retain the deployed H13, H15, H16, and H17 remediation signatures. No schema, route, configuration, `.htaccess`, manifest, scoring, role, LAB, deception, analytics, or runtime application change was made during H20.

The deployed CHIMERA baseline is sufficiently evidenced for a separate freeze review. This does not start the academic penetration test, authorize provider scanning, freeze the target, enable LAB, or authorize Kali activity.

**H-20 = PASS. Gate H = 20/20 (100%). H01–H20 = PASS. Gate H = CLOSED.**

**Next state: PRE-PENTEST BASELINE READY FOR FREEZE REVIEW.**
