# Cyber Deception

## Purpose and boundary

Phase 4 provides safe academic examples of static decoys and honeytokens. It observes interaction without changing the visitor, real application, account state, permissions, or subsequent response policy. All content is synthetic.

## Architecture

```text
Configured active path -> DecoyService -> standalone synthetic response
                                  |-> SecurityEventService -> security_events

CHM_HONEY_* material -> HoneytokenService -> hashed registry validation
                                    |-> SecurityEventService
                                    |-> honeytoken_events
```

`DecoyEndpoint`, `Honeytoken`, and `Deception` are isolated deception models. They do not query the real `Document` model. Neither service can authenticate a user or invoke Admin actions.

## Decoy lifecycle

The route must be explicitly registered and have an active matching `decoy_endpoints` row. The response mode is selected deterministically: legacy 403 page, disabled internal gateway, or synthetic debug JSON. Inactive and unknown paths return the normal safe 404 and expose no decoy content. Standalone rendering excludes real navigation, user context, and application data.

## Honeytoken lifecycle

Visible material uses `CHM_HONEY_<IDENTIFIER>`. The database stores only SHA-256 hashes and internal identifiers. The verification endpoint accepts only the constrained CHIMERA grammar, compares its hash with an active registry row, records `HONEYTOKEN_TRIGGERED`, links `honeytoken_events`, and returns a fixed revoked-credential response. Random or malformed input receives the same safe 404 as an unknown resource.

Honeytokens cannot authenticate, access documents, call external services, or represent real vendor credentials.

## Observation and RBAC

Security Admin alone can access `/security/deception` and the read-only deception APIs. Guest receives JSON 401; User and Admin receive JSON 403. Inventory responses omit hashes, token material, and dormant risk weights.

## Test methodology

E2E tests create exact fixtures only in `chimera_test`, exercise active/inactive/unknown routing, trigger one synthetic token, verify centralized and linked events, test every role boundary, confirm output lacks real data, and remove all exact fixtures afterward.

## Phase 6 adaptation

Routes and activation remain explicit and static. Phase 6 changes only the richness of synthetic content according to the active security session's Phase 5 classification. LOW is minimal, MEDIUM adds harmless context, HIGH may reveal one active registered marker, and CRITICAL may reveal the two controlled registered markers. Unknown or failed assessment falls back to LOW.

`DECEPTION_PROFILE_SELECTED`, `DECEPTION_PROFILE_CHANGED`, and `ADAPTIVE_DECOY_RENDERED` are zero-score telemetry. Repeated access to the same decoy within one active security session remains observable but contributes threat points only once. See [ADAPTIVE_DECEPTION.md](ADAPTIVE_DECEPTION.md).

## Limitations and future phases

There is no wildcard discovery, identity attribution, automated route activation, blocking, or retention automation. The separately gated Phase 7 vulnerability lab neither consumes nor modifies deception profiles.

Phase 8 measures genuine `DECOY_ACCESSED` and `HONEYTOKEN_TRIGGERED` evidence separately from adaptive bookkeeping. It reports observed profile correlation without causal claims and cannot alter decoy activation or marker exposure.

Phase 9 confirms production decoys remain synthetic, non-functional, non-authenticating, and isolated from real documents, Admin actions, environment values, and external services in both modes.
