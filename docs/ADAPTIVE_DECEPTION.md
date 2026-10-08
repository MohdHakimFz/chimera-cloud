# Adaptive Deception

## Boundary and architecture

Phase 6 consumes the stored Phase 5 assessment only when an explicitly configured Phase 4 decoy is requested:

```text
security event -> security session -> bounded assessment
                                      |
                                      v
                             AdaptiveDeceptionService
                                      |
                                      v
                       safe synthetic profile and response
```

`AdaptiveDeceptionService` is not an authorization service. Authentication, RBAC, CSRF, document ownership, uploads, legitimate APIs, accounts, and real data never call it. A CRITICAL assessment changes only synthetic decoy presentation.

## Deterministic profile policy

| Assessment | Score | Variant | Synthetic context | Registered marker exposure |
|---|---:|---|---|---|
| LOW | 0-19 | minimal | Base inert response | None |
| MEDIUM | 20-44 | contextual | Service notices and harmless references | None |
| HIGH | 45-74 | investigative | Additional breadcrumbs and synthetic component metadata | `HT-API-001` only |
| CRITICAL | 75-100 | immersive-safe | Richest inert service map and archive references | `HT-API-001` and `HT-BACKUP-001` |

Visible marker material is produced only after its CHIMERA-format hash matches an active registry record. No profile enables commands, SQL, filesystem reads, real credentials, administrative actions, or external callbacks.

## Session resolution and stability

Selection uses the existing active security session for the exact safe source hash and actor boundary. It reads the stored classification and never recalculates a score. Missing source context, no matching session, unavailable assessment, or any selection exception returns LOW.

Upgrades occur on the next decoy request after the assessment crosses a threshold. Profiles do not downgrade within the same active 30-minute security session. A new session starts at the normal safe LOW fallback.

## Feedback-loop controls

- `DECEPTION_PROFILE_SELECTED`, `DECEPTION_PROFILE_CHANGED`, and `ADAPTIVE_DECOY_RENDERED` have zero scoring weight.
- Rendering records an event but does not itself make behavior suspicious.
- The first access to each distinct decoy in a security session may contribute `DECOY_ACCESSED`; refreshes of that same decoy have `risk_delta=0`.
- Registered honeytoken presentation remains a meaningful explicit interaction and follows the Phase 5 weight.
- Scores remain bounded at 100.

The response is selected before the current decoy interaction is scored. This makes each transition explainable: observed behavior updates assessment, and a later decoy request observes the updated profile.

## Telemetry and explanation

Safe metadata records selected and previous profile, stored threat level and score snapshot, decoy identifier, response variant, and a bounded selection reason. It never records raw session material, cookies, authorization headers, marker plaintext, passwords, document contents, filesystem paths, or credentials.

Security Admin can inspect `/security/adaptive`, `/security/adaptive/{id}`, `/api/security/adaptive/summary`, `/api/security/adaptive/events`, and `/api/security/sessions/{id}/deception`. Guest receives API 401; User and Admin receive 403.

## Failure model and limitations

Adaptive failure is fail-safe toward the static/minimal LOW profile and cannot break the configured decoy route. Correlation uses a pseudonymous network source and optional actor ID; it does not prove identity or intent. Policy is fixed in application configuration and has no administrative mutation endpoint.

Phase 7 is a separate, explicit `/lab/*` system. Adaptive profiles cannot enable the lab, select its module state, make a module weaker, or route a real endpoint into it. LAB events remain outside operational sessions, so lab exercises cannot change adaptive presentation. Blocking, suspension, firewall changes, command execution, and destructive behavior remain absent.

Phase 8 counts selections, transitions, renders, and interactions observed under a profile. These are descriptive associations. Analytics cannot call selection, alter thresholds, expose markers, or influence a response.

Production readiness never selects or changes a profile. Normal and authorized-lab modes preserve the same deterministic policy and real-application isolation.
