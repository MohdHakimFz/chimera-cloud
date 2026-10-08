# Architecture

## Status and decisions

The repository was a fresh project containing only `implementation.md` and `proceed.md`. Both specifications remain unchanged. CHIMERA uses framework-free PHP 8 to minimize shared-hosting dependencies while preserving clear layers.

## Request lifecycle

1. Apache sends non-file requests to `public/index.php`.
2. Bootstrap loads environment values, autoloading, sessions, errors, and security headers.
3. The route table matches an exact method and path.
4. Middleware applies guest, authentication, CSRF, and role rules.
5. A controller validates/co-ordinates, a model uses PDO, a service handles file lifecycle, and a view escapes output.

## Final directory structure

```text
app/
  Controllers/       HTTP coordination
  Core/              request lifecycle and infrastructure
  Deception/         bounded synthetic-deception components
  Helpers/           globally available safe helpers
  Middleware/        request guards
  Models/            database access
  Security/          authentication, CSRF, headers, future telemetry
  Services/          secure document storage and lifecycle operations
config/              environment-backed settings
database/            schema and synthetic seed data
docs/                architecture and operating documentation
public/              sole document root, assets and front controller
resources/views/     server-rendered templates
routes/              route declarations
storage/logs/        non-public application logs
storage/uploads/     non-public future document storage
tests/               dependency-free checks
```

Deception implementation is deliberately split across explicit models, services, controllers, and standalone views; it does not share real document or authentication data access.

Phase 4 uses isolated models and services rather than sharing application document or authentication models. `DecoyService` resolves only configured active paths; `HoneytokenService` validates CHIMERA-format material against registry hashes and links triggers to centralized security events. Standalone decoy rendering does not include the real application navigation, authenticated user context, or document data.

## Phase 2 real application

The legitimate surface adds `/profile`, `/documents`, `/activity`, and `/api/*`. Dynamic route parameters accept positive decimal identifiers only. Controllers never use a supplied document ID alone: the model query requires both document ID and authenticated owner ID.

`DocumentService` coordinates storage and database consistency. `DocumentStorage` is the only component that constructs internal file paths and accepts only randomized filenames matching the supported extension grammar. Raw storage names and paths are not exposed to views or the API.

`Activity` is product history, not security telemetry. It records legitimate account actions in `user_activity`; Phase 3 telemetry uses the separate `security_events` model.

## Phase 3 telemetry pipeline

Security-relevant flows call `SecurityEventService`, which resolves a fixed taxonomy through `SecurityEventTaxonomy`, normalizes explicit request context, sanitizes metadata, and performs the only application-level `security_events` insert. Recording catches its own failures so telemetry cannot bypass authorization or make a successful primary operation unavailable. `SecurityEvent` provides bounded/filterable reads to the Security Admin controller, views, and APIs.

Normalized category, outcome, actor, and target fields remain in `metadata_json`; raw source addresses are excluded. Phase 5 uses the HMAC-derived `source_safe_identifier`, existing `security_sessions`, `security_events.security_session_id`, event `risk_delta`, and `security_score_contributors` fields without migration. `SecuritySessionService` owns correlation and transaction/idempotency; `ThreatScoringService` owns weights, bounds, classification, and contributor creation. Neither service is referenced by authorization or response-selection code.

## Phase 6 adaptive deception

Only configured decoy requests call `AdaptiveDeceptionService`. It resolves the active security session by the same safe source and actor boundary, reads the stored classification, applies a configuration-backed profile, and returns synthetic presentation instructions. The decoy interaction is then recorded normally, followed by zero-score selection/transition and render events. Missing or failed assessment selects the minimal LOW profile.

The dependency is one-way: decoy presentation may read assessment, but authentication, authorization, documents, profiles, Admin, and legitimate APIs do not import the adaptive service. Adaptive history is stored in existing event metadata, so the 11-table schema remains unchanged.

## Phase 7 controlled lab

`RequireLabEnabled` gates every `/lab/*` route using a default-false environment switch. Lab controllers call only `ControlledLabService`, `VulnerabilityModule`, the centralized telemetry service, and standalone lab views. Real application controllers never import lab components.

The SQLi dataset is an inline derived relation of fixed literals, IDOR uses immutable `LAB-*` records, and reflected XSS runs in an opaque-origin CSP sandbox. Registry state and audit history reuse `vulnerability_modules` and `vulnerability_state_changes`; no schema migration is required. LAB-category events deliberately bypass operational security-session correlation and always score zero.

## Data architecture

Identity and normal application tables are separated conceptually from monitoring, deception configuration, assessment, and lab configuration. The legitimate application uses `users`, `documents`, and `user_activity`; telemetry, static deception, and assessment use their own bounded tables and services. Vulnerability-module tables remain inactive placeholders. Foreign keys connect only where attribution is required.

## Verified local database topology

The Windows development application connects through PDO MySQL to MariaDB 12.2.2 at `127.0.0.1:3308`. `chimera` is the development database and uses `chimera_app`; `chimera_test` is the isolated integration database and uses `chimera_test_app`. Both accounts have database-scoped privileges only. The unrelated MySQL 8 service on port 3306 is outside the CHIMERA boundary.

HTTP E2E tests start an isolated PHP development-server process whose test router explicitly maps runtime database settings to `chimera_test`. The runner aborts unless the development database is exactly `chimera`, the test database is exactly `chimera_test`, and the connected account/server metadata match the test boundary.

## UI architecture

Views share one responsive layout. The public interface uses a restrained emerald accent and light/dark tokens. Security Operations is visibly distinct but retains the same navigation and accessibility behaviors. JavaScript is progressive enhancement for the mobile menu only.

## Phase 8 analytics and evidence

`SecurityAnalyticsService` reads existing telemetry, assessment, deception, adaptive, and LAB evidence with bounded prepared queries. `EvaluationService` supplies pure timing, median, linkage, and display-ID functions. `EvidenceExportService` serializes allowlisted minimized JSON or formula-neutralized CSV. The dependency is one-way from persisted evidence to analytics; application, scoring, adaptive, and lab behavior never consume analytics.

## Phase 9 production gate

`ProductionSecurityValidator` returns only non-secret PASS/WARNING/FAIL facts. `TransportSecurity` centralizes direct-server HTTPS detection and ignores forwarded headers. Readiness is Security Admin/CLI only and cannot mutate configuration or deploy. The public front controller provides a final generic bootstrap-failure boundary.

## Phase 10 deployment boundary

`HostingCapabilityInspector` is a read-only CLI preflight abstraction. It verifies locally observable PHP/runtime/storage facts and deliberately classifies Apache, document-root, HTTPS, database-service, certificate, logging, and infrastructure controls as `HOSTING-DEPENDENT` until measured in the authorized hosting environment. It cannot upload files, change DNS, create a database, enable the lab, or make external requests.

Deployment remains an operator-controlled sequence: capability discovery, NORMAL_SAFE deployment, live validation, separately authorized lab activation, then pentest-readiness handoff. A missing target or hosting connection blocks deployment without changing any Phase 1–9 runtime behavior. No schema change is introduced.
