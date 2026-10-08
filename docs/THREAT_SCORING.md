# Threat Scoring and Security Sessions

## Architecture and correlation

After `SecurityEventService` persists an event, `SecuritySessionService` locks that event. An event already containing `security_session_id` is complete and cannot contribute again. Otherwise, correlation uses the safe source identifier plus the exact actor boundary: an authenticated actor matches only the same user ID, while unauthenticated observations match only `user_id IS NULL`.

The service reuses the newest matching session whose `last_seen_at` is within 30 minutes. Otherwise it creates a new random internal security-session identifier. ACTIVE means activity within 30 minutes; older sessions are displayed as EXPIRED. No raw PHP session ID, cookie, authorization header, or authentication material participates.

## Scoring policy

| Event | Points | Rationale |
|---|---:|---|
| `ACCESS_DENIED` | 3 | Low-confidence unauthenticated protected access |
| `LOGIN_FAILURE` | 5 | Failed authentication can be accidental or probing |
| `DOCUMENT_UPLOAD_REJECTED` | 5 | Upload failed a security control |
| `ROLE_ACCESS_DENIED` | 10 | Attempt outside an assigned privilege boundary |
| `SECURITY_RELEVANT_APPLICATION_ERROR` | 10 | Security-relevant operation failure |
| `OWNERSHIP_ACCESS_DENIED` | 12 | Attempt outside an object ownership boundary |
| `CSRF_REJECTED` | 12 | Invalid state-changing request provenance |
| `DOCUMENT_INTEGRITY_FAILURE` | 20 | Stored data failed integrity verification |
| `DECOY_ACCESSED` | 20 | Synthetic surface has no normal application purpose |
| `HONEYTOKEN_TRIGGERED` | 35 | High-confidence interaction with a non-functional synthetic marker |

All other events contribute zero. Successful ordinary behavior is correlated for context but does not increase score.

The update is `min(100, max(0, current + delta))`. Thresholds are LOW 0–19, MEDIUM 20–44, HIGH 45–74, and CRITICAL 75–100. These labels describe observed behavior and do not prove identity or intent.

## Explainability and idempotency

Every positive delta creates a `security_score_contributors` row containing the rule, event number, rationale, delta, and timestamp. Current score equals the bounded sum of contributors. The event row is selected `FOR UPDATE`; processing succeeds only while `security_session_id IS NULL`. Correlation, contributor insert, score update, and event linkage commit together, preventing refreshes or retries from adding a second contribution.

## Failure and Phase 6 integration

Assessment failures are logged generically after telemetry has been persisted. They do not affect the primary response. Scoring services have no dependency path into authentication, authorization, profiles, documents, or decoy resolution.

Phase 5 does not block, suspend, rate-limit, alter permissions, activate decoys, or remediate. Phase 6 reads the stored assessment only when a configured synthetic decoy is rendered. `DECEPTION_PROFILE_SELECTED`, `DECEPTION_PROFILE_CHANGED`, and `ADAPTIVE_DECOY_RENDERED` contribute zero. The first access to a particular decoy in an active security session contributes the documented `DECOY_ACCESSED` weight; refreshes of that same decoy are recorded with zero delta to prevent artificial feedback amplification.

Assessment still has no dependency path into authentication, authorization, profiles, documents, legitimate APIs, or account state. Phase 7 LAB events bypass security-session correlation and scoring entirely, so authorized demonstrations cannot change an operational score or adaptive profile.

Phase 8 reconstructs progression only from persisted contributors and compares the bounded sum with the stored score. A disagreement becomes an evidence-integrity warning; analytics never changes rules, weights, thresholds, contributors, or history.

Production readiness does not change weights, thresholds, correlation, or contributors. Authorized LAB events remain zero-score and readiness results are never scoring inputs.
