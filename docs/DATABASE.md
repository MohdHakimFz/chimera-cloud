# Database

`database/schema.sql` creates normalized InnoDB tables with utf8mb4, indexes, and foreign keys. `database/seed.sql` adds three synthetic role accounts, inert decoy definitions, hashed synthetic honeytokens, and one disabled lab-module definition.

Phase 2 required no schema alteration because `users`, `documents`, and `user_activity` already contain the required normalized fields. The seed now adds synthetic `ACCOUNT_CREATED` activity for the three seed accounts. It deliberately does not seed document rows because a document record without its matching private file would be inconsistent.

## Table groups

- Application: `users`, `documents`, `user_activity`
- Monitoring: `security_sessions`, `security_events`, `security_score_contributors`
- Deception: `decoy_endpoints`, `honeytokens`, `honeytoken_events`
- Lab/remediation: `vulnerability_modules`, `vulnerability_state_changes`

The schema script is destructive by design for an empty laboratory setup because it drops its own named tables before recreation. Do not run it against a database containing results that must be retained. Production upgrades should later use versioned migrations.

Phase 3 required no schema change. `security_events` stores fixed event type, severity, endpoint, method, safe source identifier, bounded user-agent summary, description, and JSON metadata. New metadata contains normalized category, outcome, optional actor ID, and optional target identifiers; the direct-peer address is used only transiently to derive the safe identifier and is not persisted in metadata. Beginning in Phase 5, eligible events receive deterministic bounded scoring through correlated contributor rows.

Phase 4 also requires no schema change. `decoy_endpoints` is the static route registry. `honeytokens` stores only SHA-256 hashes and internal identifiers; visible material uses the CHIMERA-only `CHM_HONEY_*` namespace. `honeytoken_events` links a validated token interaction to its security event. Dormant `risk_weight` values are neither read nor exposed by Phase 4.

Phase 5 requires no schema change. `security_sessions` holds the pseudonymous correlation context, bounded score, classification, event count, and timestamps. `security_events.security_session_id` marks an event processed exactly once and `risk_delta` stores its deterministic contribution. `security_score_contributors` stores rule code, event-referencing explanation, delta, and timestamp. Lifecycle status is derived: last activity within 30 minutes is ACTIVE; older sessions are EXPIRED.

Phase 6 also requires no schema change. Adaptive decisions and profile transitions are normalized security events whose safe metadata records the selected profile, previous profile, threat level, decoy identifier, variant, and reason. Their `risk_delta` is always zero. The latest `ADAPTIVE_DECOY_RENDERED` event provides profile history for a security session; no runtime migration or additional database privilege is required.

Phase 7 requires no schema change. `vulnerability_modules` contains the three stable synthetic module definitions and their `VULNERABLE`/`REMEDIATED` state. `vulnerability_state_changes` records Security Admin actor, previous state, new state, reason, and timestamp. SQLi training rows are inline query literals rather than a table, and IDOR records are immutable application constants, so no lab query can select real tables. LAB security events keep `security_session_id` null and `risk_delta` zero.

JSON columns require a current MySQL/MariaDB release. Timestamps are stored by the database; the application timezone affects display and application-generated time only.

## Local verified databases

Phase 2.5 verified MariaDB 12.2.2 at `127.0.0.1:3308`:

- `chimera`: development data, synthetic seed, runtime account `chimera_app`
- `chimera_test`: unseeded destructive integration data, test account `chimera_test_app`

Both schemas contain the same 11 expected tables, required indexes, and nine foreign keys. Credentials remain only in the ignored local `.env`; no root account is used at runtime. Test runners require the exact name `chimera_test` and verify the active database, port, and account before mutation. The schema file drops its named tables and therefore must not be rerun against `chimera` as an upgrade mechanism.

## Document records

`documents.user_id` is the ownership boundary. `original_name` is display metadata only. `storage_name` is a unique random server-generated filename. `mime_type`, `size_bytes`, and `checksum_sha256` are derived and verified by the server.

Application queries for private documents bind both primary key and owner key. Admin overview queries may read document metadata joined to account metadata but never retrieve `storage_name`, file contents, password hashes, or session information.

## Activity records

`user_activity` describes legitimate product actions and may contain small JSON metadata such as document ID, original display name, size, or a missing-file consistency flag. It must never contain passwords, tokens, session IDs, internal paths, or contents. It is distinct from `security_events`.

## Phase 8 evidence queries

No migration was required. Contributor labels retain the originating event number, enabling analytics to attach a contributor to one event without duplicating the timeline. A missing link or bounded-score mismatch is surfaced as an integrity warning. LAB evidence remains identifiable by taxonomy metadata and a null `security_session_id`. Database privileges were not broadened; analytics issues no structural or evidence-mutation SQL.

## Phase 9 database gate

No schema change was required. Readiness uses read-only checks for connectivity, a non-root identity, and all 11 tables. Local runtime grants remain database-scoped without administrative privileges. See [PRODUCTION_DATABASE.md](PRODUCTION_DATABASE.md).

## InfinityFree production initialization

The 11-table `schema.sql` is explicitly **INITIALIZATION ONLY**: it drops all named CHIMERA tables before recreating them. Import it once only after confirming that the selected production database is empty. It is not an upgrade/migration mechanism.

Do not import development `seed.sql`. `production_reference_seed.sql` contains only three decoys, two synthetic honeytoken hashes, and three initially `REMEDIATED` vulnerability-module definitions. Its eight `WHERE NOT EXISTS` inserts are idempotent and deliberately do not update existing module state or operational evidence. Security Admin provisioning remains a separate operator action with no seeded credential.
