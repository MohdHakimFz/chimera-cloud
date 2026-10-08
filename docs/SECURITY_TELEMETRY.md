# Security Telemetry

## Scope

Application flows emit normalized events through `SecurityEventService`; the service resolves semantics through `SecurityEventTaxonomy` and persists them in `security_events`. Phase 5 adds deterministic, bounded threat scoring to eligible correlated events. Automated blocking, account action, and authorization changes remain absent.

## Taxonomy and severity

| Category | Events | Severity |
|---|---|---|
| Authentication | `LOGIN_SUCCESS`, `LOGOUT`, `REGISTRATION_SUCCESS` | INFO |
| Authentication | `LOGIN_FAILURE` | MEDIUM |
| Authorization | `ACCESS_DENIED` | LOW |
| Authorization | `ROLE_ACCESS_DENIED`, `OWNERSHIP_ACCESS_DENIED` | MEDIUM |
| Request security | `INVALID_REQUEST` | LOW |
| Request security | `CSRF_REJECTED` | MEDIUM |
| Document security | Successful upload, download, and delete events | INFO |
| Document security | `DOCUMENT_UPLOAD_REJECTED` | LOW |
| Document security | `DOCUMENT_INTEGRITY_FAILURE` | HIGH |
| Account | `PROFILE_UPDATED` | INFO |
| Application | `SECURITY_RELEVANT_APPLICATION_ERROR` | HIGH |
| Deception | `DECOY_ACCESSED` | MEDIUM |
| Deception | `HONEYTOKEN_TRIGGERED` | HIGH |
| Adaptive deception | `DECEPTION_PROFILE_SELECTED`, `DECEPTION_PROFILE_CHANGED`, `ADAPTIVE_DECOY_RENDERED` | INFO |
| Authorized lab | `LAB_MODULE_ACCESSED`, `LAB_VULNERABILITY_INTERACTION`, `LAB_REMEDIATED_TEST`, `LAB_MODULE_STATE_CHANGED` | INFO |

Severity remains a fixed property of event semantics. Beginning in Phase 5, contributing events receive a documented `risk_delta` and correlation reference after the original telemetry insert. This does not change their event type, severity, description, endpoint, or metadata.

## Stored context

Core columns hold event type, severity, method, normalized endpoint, bounded user-agent summary, description, and a SHA-256 source identifier. When `TELEMETRY_HASH_KEY` is configured, the identifier uses HMAC-SHA-256. Structured metadata holds category, outcome, optional actor user ID, optional target type/identifier, and small event-specific facts. Raw source addresses are not persisted in new event metadata and neither raw nor safe source identifiers are presented through telemetry or deception views/APIs.

The service ignores `X-Forwarded-For`, `Forwarded`, and similar headers. `REMOTE_ADDR` is the transient direct-peer input used to derive the safe correlation identifier; it is not retained as event metadata. A reverse-proxy deployment must not claim end-client attribution without a defined and enforced trusted-proxy policy.

## Safety rules

Telemetry call sites pass explicit metadata; the service never copies complete request bodies or header collections. Sensitive metadata keys—including password, token, CSRF, cookie, authorization, session, credential, content, path, and storage variants—are dropped. Values are bounded and control characters removed.

Do not record passwords, hashes, cookies, CSRF values, authorization headers, database credentials, document contents, internal paths, or raw PHP session identifiers. UI output is escaped and API output is JSON encoded. Recording failures emit only a generic server log message and do not change the primary response.

## Access control

Only the exact `security_admin` role can access:

- `/security`
- `/security/events/{id}`
- `/api/security/events`
- `/api/security/events/{id}`
- `/api/security/summary`

User and Admin roles do not inherit Security Admin access. Event IDs are read-only and remain behind the same exact-role middleware.

## Retention

No automatic deletion is scheduled in Phase 3. For the academic prototype, review storage growth and establish a documented backup and retention window before deployment. Any future purge must be an explicit administrative operation scoped by timestamp and tested outside the development database first.

## Assessment integration and deferred capabilities

Phase 5 correlates eligible events into bounded security sessions and assigns documented deterministic `risk_delta` values. Phase 6 adaptation events describe profile decisions but always contribute zero. Selected profile, previous profile, threat level, score snapshot, decoy identifier, and reason are bounded metadata; marker plaintext is never copied into telemetry.

Automatic blocking, account action, route activation, real-application response changes, and identity attribution remain intentionally absent.

Phase 7 LAB-category events are explicitly authorized-training observations, not evidence of a real incident. They retain bounded module facts but are not correlated to operational security sessions and always have `risk_delta=0`. Payloads, raw source addresses, real session material, credentials, and synthetic marker plaintext are not recorded.

Phase 8 treats these rows as immutable evidence, projects only an allowlisted metadata subset, and attaches score contributors without duplicate timeline rows. Integrity disagreement is reported rather than repaired. See [SECURITY_ANALYTICS.md](SECURITY_ANALYTICS.md).

Phase 9 revalidated exclusion of request bodies, cookies, authorization/CSRF values, passwords, document contents, database secrets, and honeytoken plaintext. Production readiness requires a long telemetry hashing key; source correlation still ignores untrusted proxy headers. The H13 privacy hardening also excludes raw source addresses from persistence and presentation while retaining internal HMAC correlation.
