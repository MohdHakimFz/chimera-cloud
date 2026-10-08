# Route Security Matrix

Legend: **Guest** public, **Auth** any authenticated user, **Admin** exact ADMIN, **SecAdmin** exact SECURITY ADMIN, **Lab gate** requires the environment switch. Every listed GET is read-only except that decoy/lab interaction GETs intentionally record telemetry; they do not mutate real application state.

| Routes | Method | Access | CSRF | Domain / behavior |
|---|---|---|---|---|
| `/`, `/about` | GET | Guest | — | Public read |
| `/login`, `/register` | GET | Guest-only | — | Authentication forms |
| `/login`, `/register` | POST | Guest-only | Yes | Authentication mutation |
| `/logout` | POST | Auth | Yes | Session invalidation |
| `/dashboard`, `/profile`, `/documents`, `/activity` | GET | Auth | — | Real application read |
| `/profile` | POST | Auth | Yes | Own-profile allowlisted update |
| `/documents` | POST | Auth | Yes | Secure upload |
| `/documents/{id}` | GET | Auth + owner | — | Owned metadata |
| `/documents/{id}/download` | GET | Auth + owner | — | Integrity-checked attachment |
| `/documents/{id}/delete` | POST | Auth + owner | Yes | Quarantine-first deletion |
| `/api/me`, `/api/documents`, `/api/documents/{id}` | GET | Auth / owner | — | Bounded legitimate JSON API |
| `/admin` | GET | Admin | — | General administration read |
| `/security`, `/security/events/{id}` | GET | SecAdmin | — | Telemetry read |
| `/api/security/events`, `/api/security/events/{id}`, `/api/security/summary` | GET | SecAdmin | — | Telemetry JSON read |
| `/security/deception` | GET | SecAdmin | — | Static deception read |
| `/api/security/deception/summary`, `/api/security/decoys`, `/api/security/honeytokens`, `/api/security/deception/events` | GET | SecAdmin | — | Deception JSON read |
| `/security/threats`, `/security/threats/{id}` | GET | SecAdmin | — | Assessment read |
| `/api/security/sessions`, `/api/security/sessions/{id}`, `/api/security/threat-summary` | GET | SecAdmin | — | Assessment JSON read |
| `/security/adaptive`, `/security/adaptive/{id}` | GET | SecAdmin | — | Adaptive evidence read |
| `/api/security/adaptive/summary`, `/api/security/adaptive/events`, `/api/security/sessions/{id}/deception` | GET | SecAdmin | — | Adaptive JSON read |
| `/security/lab` | GET | SecAdmin | — | Lab status/management read |
| `/security/lab/modules/{id}/state` | POST | SecAdmin | Yes | Allowlisted lab-state mutation |
| `/security/analytics`, `/security/analytics/sessions/{id}` | GET | SecAdmin | — | Read-only analytics |
| `/api/security/analytics/summary`, `/timeline`, `/sessions/{id}`, `/lab` | GET | SecAdmin | — | Bounded analytics JSON |
| `/api/security/analytics/export` | GET | SecAdmin | — | Bounded read-only JSON/CSV export |
| `/security/deployment-readiness` | GET | SecAdmin | — | Non-secret configuration status |
| `/admin-old`, `/internal`, `/api/debug` | GET | Guest | — | Synthetic decoy + telemetry |
| `/api/debug/verify` | GET | Guest | — | Synthetic registry trigger + telemetry |
| `/lab`, `/lab/robots.txt`, `/lab/sqli`, `/lab/idor`, `/lab/xss` | GET | Guest + Lab gate | — | Controlled synthetic lab + zero-score LAB telemetry |

Unmatched routes return safe 404. A path registered for a different method returns 405 and an `Allow` header. Guest API role failures return JSON 401; authenticated wrong-role API requests return 403. No Security Admin capability is inherited by ADMIN, and SECURITY ADMIN does not inherit `/admin`.
