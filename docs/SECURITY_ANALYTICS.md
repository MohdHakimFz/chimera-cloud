# Security Analytics

## Architecture and boundary

Phase 8 is a read-only evidence layer over persisted Phase 3–7 output.

```text
security_events + security_sessions + security_score_contributors
decoy/honeytoken evidence + vulnerability registry/history
                              |
                              v
                 SecurityAnalyticsService
                    | metrics / timeline / evaluation
                              v
                   EvidenceExportService
                    | dashboard | JSON | CSV
```

`SecurityAnalyticsService` owns bounded prepared queries, aggregation, timeline construction, session analysis, evidence-integrity checks, and lab comparison. `EvaluationService` owns display identifiers, durations, medians, and contributor linkage. `EvidenceExportService` owns the fixed export allowlist, serialization, data minimization, and CSV-cell neutralization. Controllers contain no analytics SQL.

No schema migration was required. Analytics never creates events, rescores sessions, selects deception profiles, enables the lab, or changes vulnerability state.

## Data domains

- **Operational security:** authentication, authorization, request/document security, security sessions, and score contributors.
- **Cyber deception:** genuine decoy/honeytoken interaction and zero-score adaptive selection, transition, and render observations.
- **Controlled lab:** `LAB_*` events, module state, and state history. LAB evidence remains outside operational sessions and operational timing/score metrics.

## Metrics and formulas

The dashboard reports total events; event category, severity, type, and daily grouping; session lifecycle and threat-level distribution; average, minimum, maximum, and median score; thresholds reached; contributor frequency; deception/adaptive counts; and controlled-lab comparison.

```text
Detection Latency = first positive contributor - first persisted session event
Time to Deception = first DECOY_ACCESSED - first positive contributor
Time to Honeytoken = first HONEYTOKEN_TRIGGERED - first positive contributor
```

A same-event positive detection is `0` seconds. Missing evidence is `null` in JSON and `N/A` in the UI; it is never substituted with zero. Aggregates include only measurable sessions.

Score progression uses persisted contributors, attaches each contributor to its referenced `Event #...`, and bounds the running sum to 0–100. A mismatch from the stored score or an unattached contributor produces an integrity `WARNING`; history is not rewritten.

Deception analytics distinguishes genuine interaction from profile bookkeeping. Profile associations are descriptive, not causal. Interaction depth is displayed as separate evidence counts rather than an invented score. LAB evaluation reports recorded vulnerable/remediated observations and displays `INSUFFICIENT EVIDENCE` when facts are absent.

## Timeline, filtering, and performance

The unified timeline orders by `created_at` and event ID for deterministic ties. Contributors attach to their event rather than becoming duplicate timeline rows. LAB and operational evidence are visibly labeled.

Filters support exact start/end dates, category, event type, severity, threat level, adaptive profile, and allowlisted lab module. Dates require `YYYY-MM-DD`, both endpoints are required together, and the range is limited to 366 days. Invalid values fail closed: the browser dashboard displays no result data and APIs/exports return `422 INVALID_FILTER`. Request values are bound through native prepared statements.

Timelines are capped at 200 rows, session evidence at 500 events/contributors, LAB reads at 500 events/100 state changes, and every export type is capped at 1,000 rows. Dashboard aggregations avoid per-row database lookups.

## UI, APIs, and exports

Security Admin browser routes are `/security/analytics` and `/security/analytics/sessions/{id}`. Read APIs are:

- `/api/security/analytics/summary`
- `/api/security/analytics/timeline`
- `/api/security/analytics/sessions/{id}`
- `/api/security/analytics/lab`
- `/api/security/analytics/export?type=...&format=json|csv`

Export types are exactly `security_events`, `security_sessions`, `score_contributors`, `deception_interactions`, `adaptive_timeline`, `lab_evaluation`, and `session_evidence`. Event-derived exports accept the event-filter set; session/contributor exports accept date and threat-level filters. A `session_evidence` request with a positive `session_id` exports that session; the generic dashboard request without an ID exports exactly the deterministic latest session, or an empty data array when no session exists. Unsupported filters and malformed IDs fail closed. The export endpoint uses `event_type` for an event-type constraint so it cannot collide with the export `type` parameter. Stable display labels use `SEC-00000001`, `EVT-00000001`, and `CON-00000001`; they are not authorization tokens.

Guest API access returns 401, USER and ADMIN receive 403, and SECURITY ADMIN is allowed. Outputs omit password data, cookies, raw sessions, authorization/CSRF values, token hashes/material, environment/database configuration, storage paths/names, and document content. Metadata is projected through a safe-field allowlist.

## CSV formula-injection protection

CSV quoting is insufficient against spreadsheet interpretation. If a cell’s first non-whitespace character is `=`, `+`, `-`, or `@`, CHIMERA prefixes the entire value with a single quote before CSV serialization. This deterministic policy is covered by tests for all four prefixes and leading whitespace.

## Read-only guarantee and limitations

Static checks reject evidence-table mutation SQL and calls into scoring, adaptation, or lab mutation. Database and HTTP tests snapshot scores, contributor counts, and module state around analytics reads. Historical evidence is immutable input.

Source identifiers are used only internally for correlation. Analytics queries, HTML, APIs, JSON exports, and CSV exports neither select nor present raw or pseudonymous source identifiers. Stable evidence IDs provide presentation references without disclosing correlation material. Correlation does not establish human identity or intent. Persisted association cannot establish causal effectiveness. There is no external SIEM, ML/LLM analysis, automated remediation, background queue, or retention purge.

Phase 9 revalidated exact RBAC, prepared allowlisted filters, result/export bounds, JSON/CSV typing, non-cacheable exports, formula-prefix neutralization, secret exclusion, and the read-only boundary.
