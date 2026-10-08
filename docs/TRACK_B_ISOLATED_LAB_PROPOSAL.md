# PROJECT CHIMERA — Isolated Track B Lab Proposal (Phase 1)

**Status: PROPOSAL / PREREQUISITES ONLY. LAB NOT DEPLOYED.** This document plans a separate, student-controlled CHIMERA clone for the NWC3293 assessment. It does not authorize an active scan, controlled exploit, production request, or vulnerability-module activation. The production target and its frozen 128-file manifest remain untouched. Track A Reconnaissance and Scanning are reported complete; Track B Gaining Access has **not** started. The production LAB remains disabled.

## 1. Architecture findings from the local repository

CHIMERA is a framework-free PHP 8 application. `public/index.php` loads `bootstrap/app.php`, which reads `BASE_PATH/.env`, starts a PHP session, sets security headers, and loads `routes/web.php`. Apache rewrite is used for clean routes; `public/` is the preferred document root. `app/Core/Database.php` uses PDO MySQL with `DB_HOST`, `DB_PORT`, `DB_DATABASE`, `DB_USERNAME` and `DB_PASSWORD`. `app/Services/HostingCapabilityInspector.php` lists PDO, pdo_mysql, mbstring, fileinfo, json, session and hash as required PHP extensions. `DocumentStorage` requires an absolute private path, and `PRIVATE_OUTSIDE_WEBROOT` allows a separate file volume outside `public/`.

`database/schema.sql` defines **11 tables** and begins by dropping those named tables: it is **initialization-only and destructive**. The existing `database/seed.sql` inserts accounts with repository-known hashes and modules in `VULNERABLE` state; **do not use it as the lab account seed**. `database/production_reference_seed.sql` contains only synthetic decoy/honeytoken reference records and three initially `REMEDIATED` modules, with no users or documents. A later lab-specific provisioning method must create unique synthetic users with fresh, private passwords and hashes. Synthetic documents should be created through the clone's normal application workflow so database metadata and physical files agree.

`routes/web.php` separates guest/authenticated/role-protected application routes from default-disabled `/lab/*` routes. `RequireLabEnabled` checks `VULNERABILITY_LAB_ENABLED`, default false; Security Admin module-state controls are distinct from that global switch. The synthetic SQLi, IDOR and XSS modules are isolated from normal document/account data, but even isolated deployment must begin with the global LAB switch **false** and modules **REMEDIATED**. Later activation is a separately authorized Track B step, never a production change.

No existing Dockerfile, Compose deployment or lab-specific environment was found. The current Windows development MariaDB databases (`chimera` and `chimera_test`) are **not** lab targets. A repository-root `.env` exists but was **not read** for this proposal and must never be copied into a lab image.

## 2. Recommended deployment method

**Preferred:** a dedicated Linux **target VM** attached to a verified VMware **host-only** network, running a small Docker Compose stack containing (1) PHP/Apache CHIMERA, and (2) MariaDB. Kali is a separate VM on that same host-only segment. This combines reproducible app/DB setup with a strong VM network boundary. The target VM should have no default route or Internet egress during testing; any temporary network access for OS/image acquisition must occur *before* the test environment is declared isolated, then be disabled and re-verified. Docker's DB service has **no published host port**. The app publishes only one chosen HTTP port, bound to the target VM's **verified host-only IP**, never `0.0.0.0` or a bridged/NAT interface. Host firewall rules restrict that port to the verified Kali address. Do not enable IPv6 exposure or forwarding inadvertently.

**Fallback:** a dedicated Linux target VM with Apache/PHP/MariaDB installed directly, still host-only, no default route, separate lab database and the same path/credential controls. Use this if Compose cannot be installed or its bind/isolation behavior cannot be verified. A Windows-host Docker Desktop stack is less preferred because VMware-to-host port binding and firewall exposure are easier to misconfigure; consider it only after a documented bind, routing and firewall proof. Do not treat `192.168.244.0/24` as host-only merely because Kali currently reports `eth0 = 192.168.244.128/24`.

```text
                    VERIFIED VMware host-only segment (no uplink)
  Kali VM (attacker)  <---- only authorized lab HTTP ---->  Target Linux VM
  IP to re-verify                                      host-only IP to assign
                                                        |
                                         Docker Compose inside target VM
                                         +-----------------------------+
                                         | PHP/Apache: CHIMERA clone   |
                                         | private app/file volumes    |
                                         | MariaDB: chimera_lab        |
                                         | DB port NOT published       |
                                         +-----------------------------+

  Windows development host: source/staging control only
  InfinityFree production, Windows dev DB, chimera_test: NOT CONNECTED
```

This is a proposed logical diagram, not a verified network map. The Kali IP is an observation, **not** a lab target IP or proof of isolation. No lab address is assigned in this phase.

## 3. Proposed file and data boundaries

Only **after operator approval**, create new lab-specific files; do not change frozen `app/`, `bootstrap/`, `config/`, `public/`, `resources/`, `routes/`, `.htaccess`, database schema, or current `.env`:

| Proposed new file/path | Purpose and guard |
|---|---|
| `lab/compose.yaml` | Two-service app/DB stack; explicit host-only bind for app, no DB port, separate named volumes, pinned reviewed image versions; no `latest` tags. |
| `lab/Dockerfile` and `lab/apache-vhost.conf` | PHP 8 + required extensions, `mod_rewrite`, DocumentRoot at clone `public/`, deny dotfiles and directory listing; no runtime source edits. |
| `lab/prepare-build.ps1` (or equivalent guarded copy process) | Stage only frozen-manifest runtime files into a lab build context, verify source hashes, and exclude root `.env`, private documents, logs, test data, `dist/`, `node_modules/`, credentials and production archives. Do not run in Phase 1. |
| `lab/.env.example` | Non-secret **lab-only template** showing variables and placeholders. Never copy production `.env`. |
| `lab/.env.runtime` (ignored, created later on target VM) | Unique generated lab DB and telemetry secrets, verified target IP/URL; never committed, printed, deployed to production or included in evidence. |
| `lab/.gitignore` / build-context ignore | Exclude runtime secret file, generated build context, volumes, downloaded images, local evidence and backups. |
| `lab/provision-users.php` or guarded equivalent | Later interactive/secret-input provisioning of two standard USERs and one Security Admin using fresh hashes; no plaintext credential in repo or command history. This needs a separate review before implementation. |
| `docs/TRACK_B_ISOLATED_LAB_RUNBOOK.md` | Later exact versioned startup, network-check, provisioning, backup/reset, shutdown and recovery commands after topology approval. |

Do **not** create any of those runtime/deployment files in this planning phase. The only new file in Phase 1 is this proposal. A later build may consume the existing `database/schema.sql` **only in a new, verified empty `chimera_lab` volume** and then import the synthetic-only `production_reference_seed.sql` into that same lab database. Never import a production SQL dump, development DB backup, existing user table, private document, session or telemetry data. Never use `database/seed.sql` account passwords/hashes as the lab credential set. The DB runtime account must have only lab-database privileges; no root account is used by the PHP app.

## 4. Lab-specific configuration design — template, not applied

The app's bootstrap loads `BASE_PATH/.env` but does not override already-present process environment values. The planned Compose service should inject **lab-only** environment values and the build context must **exclude any root `.env`**. The following is a design sketch with placeholders, **not** a generated credential file or deployable config:

```text
APP_ENV=local
APP_DEBUG=false
APP_URL=http://<VERIFIED_LAB_TARGET_IP>:<APP_PORT>
APP_BASE_PATH=
APP_TIMEZONE=Asia/Kuala_Lumpur
HTTPS_ENFORCE=false
DB_HOST=db
DB_PORT=3306
DB_DATABASE=chimera_lab
DB_USERNAME=<DEDICATED_LAB_DB_USER>
DB_PASSWORD=<FRESH_PRIVATE_LAB_SECRET>
DB_CHARSET=utf8mb4
SESSION_NAME=chimera_lab_session
SESSION_SECURE=false
SESSION_SAMESITE=Lax
SESSION_SAVE_PATH=/srv/chimera/storage/sessions
DEPLOYMENT_STORAGE_MODE=PRIVATE_OUTSIDE_WEBROOT
WEBROOT_DENIAL_VERIFIED=false
DOCUMENT_STORAGE_PATH=/srv/chimera/storage/uploads/documents
DOCUMENT_MAX_BYTES=5242880
DOCUMENT_ALLOWED_EXTENSIONS=pdf,txt,csv,md
TELEMETRY_HASH_KEY=<FRESH_PRIVATE_LAB_KEY_AT_LEAST_32_CHARACTERS>
VULNERABILITY_LAB_ENABLED=false
```

The HTTP/`SESSION_SECURE=false` combination is a **documented isolation-specific difference**, not production parity. The isolated target must not be Internet reachable. If a later exercise requires production-like TLS/cookie behavior, design a private TLS termination and Kali trust procedure separately; do not weaken or alter production settings. `APP_URL`, `DB_HOST` and storage paths must be checked at runtime before any test. No production origin, `sql300` host, Windows dev DB port 3308, `chimera`, or `chimera_test` may appear in lab runtime connection settings.

Kali shell template for a **future verified** target (do not substitute an unverified address or run it now):

```bash
export TARGET_URL="http://LAB_TARGET_IP"
export TARGET_HOST="LAB_TARGET_IP"
```

If the approved app listener is not port 80, the eventual `TARGET_URL` must include the **verified** port. `LAB_TARGET_IP` is deliberately a placeholder, not `192.168.244.128` (that is the reported Kali address). Never point these variables to InfinityFree or a DNS-derived provider IP.

## 5. Network verification gate

**Blocking prerequisite:** the VMware network mode is not verified. Before deployment, the operator must document VMware Virtual Network Editor settings and the exact VMnet used by **both** Kali and target; confirm it is host-only with no physical uplink/bridging/NAT for the target. Verify actual Kali and target addresses, subnet masks, interfaces, routing tables, DNS/IPv6 routes and default gateways. A reported Kali `/24` address alone does not establish isolation. Reserve one nonconflicting target IP only after that check.

After deployment approval, verify that the target VM and app container have no Internet/default route while testing; the only externally reachable service is the chosen app port on the verified target host-only address, and the MariaDB port is not reachable from Kali/Windows networks. Confirm the target is not reachable via the Windows LAN, Wi-Fi or public Internet; verify Windows/VM firewalls and Docker port bindings. Record the *method and result* without probing provider systems. Any unexpected route, listener or external reachability is a **STOP** condition. Do not run Nmap or other active scanners for the isolation check before a separate approved scope is in place; use configuration/routing/listener inspection and one explicitly authorized lab-only connectivity check later.

## 6. Proposed deployment sequence — not executed

1. **Approve topology and scope.** Choose host-only VMnet, target VM resources/OS, Compose availability, app port and synthetic account set. Record owner, testing window and stop contact.
2. **Stage prerequisites while offline from testing.** Acquire reviewed/pinned PHP/Apache and MariaDB images or packages on the target VM under controlled conditions; then remove temporary NAT/bridged access and verify host-only mode again.
3. **Stage the frozen source safely.** Use an explicit allowlist derived from the frozen manifest; compare SHA-256 hashes. Do not copy `.env`, production data, Windows dev DB, archives or evidence. Keep the clone separate from the frozen source tree.
4. **Create lab-only configuration.** Generate fresh unique lab secrets privately, set `DB_HOST=db`, DB name `chimera_lab`, private storage path and `VULNERABILITY_LAB_ENABLED=false`; verify no production URL/host/credentials. Do not commit the runtime secret file.
5. **Build services, but do not expose yet.** Configure Apache `public/` root and required PHP extensions; configure MariaDB with its own empty volume, no published DB port, least-privilege app account and health checks. Confirm app port binds only to verified host-only IP.
6. **Initialize synthetic database once.** Confirm exact service/database/volume identity and backup/empty state; only then import `schema.sql` into the new lab DB, followed by the synthetic reference seed. Verify 11 tables, three REMEDIATED modules, no real accounts/documents. The schema's DROP statements make this step unsafe anywhere else.
7. **Provision synthetic identities/data.** Create two unique USER accounts and one Security Admin with fresh private passwords/hashes using a guarded lab-only process. Create a tiny harmless document through a USER workflow. No imported real data.
8. **Validate normal mode.** Confirm health, login, documents, role separation and LAB disabled without exploit requests; verify logs do not expose secrets and writable paths stay private. Record lab/production differences explicitly.
9. **Verify isolation from Kali.** Only after network checks, perform a single approved connection to the verified target IP/port; confirm no other interface or DB exposure. Capture non-secret topology/config evidence.
10. **Snapshot the known-good baseline.** Record image digests, source manifest hash, DB/data-volume snapshot method, account fixture inventory and LAB=false. Only after this is Track B scanning or controlled exploitation eligible for its own approval.

None of these steps has been run. No software was installed and no target IP, Compose service, database or account was created in Phase 1.

## 7. Startup, shutdown, evidence, reset and recovery design

- **Startup (later runbook):** verify host-only/no egress first, load lab-only runtime secrets, start DB then app with fixed Compose project name, wait for DB health, inspect port binding and LAB=false, then authorize one normal synthetic login. Do not start if any check fails.
- **Shutdown:** stop application exposure and DB gracefully; preserve volumes and evidence by default. Stopping is not a reset and must not erase findings. Do not use broad volume-pruning commands.
- **Evidence:** keep `B-REC-*`, `B-SCAN-*`, `B-GA-*` and defensive evidence under the existing `evidence/pentest/track-b/` structure or a dedicated target-VM evidence volume, not inside the serving webroot. Record clone version, image digests, LAB/module state, test time, exact lab IP/port, command profile, result and redaction. Do not save passwords, session/CSRF values, token material or unrelated data.
- **Reset:** only after preserving needed evidence and verifying exact lab-only volume names. Restore an approved snapshot or recreate a **dedicated `chimera_lab` volume** and reinitialize with synthetic data. Never run `schema.sql` against `chimera`, `chimera_test` or production. Reset is a separately approved destructive lab operation; no reset command is issued here.
- **Recovery:** if the lab becomes unstable or escape/exposure is suspected, stop the app listener, disconnect the host-only adapter or firewall the target, preserve logs/evidence, verify no production credential/config was present, restore the last clean snapshot, and re-run isolation/readiness checks. Do not pivot to production for diagnosis.

## 8. Allowed testing scope and readiness criteria

**Future lab scope:** only the verified target VM, its CHIMERA app listener and synthetic data. Deeper Nmap/Nikto/Nuclei/fuzzing and controlled LAB demonstrations are possible **only after separate reviewed Track B test plans**, bounded tool profiles and operator authorization. No host OS shell/persistence, unrelated networks, Windows host services, production, InfinityFree infrastructure or other tenants are implicitly authorized. Initially keep `VULNERABILITY_LAB_ENABLED=false` and all modules REMEDIATED. Later intentional activation requires an isolated-only approval, state record and reset plan.

Do **not** begin active scanning or controlled exploitation until all are true:

- [ ] VMware host-only topology and actual Kali/target IPs verified; no target default route, IPv6 escape, NAT/bridge or Internet reachability during testing.
- [ ] App port bound only to verified target host-only IP; DB port unpublished; firewall allows only the approved Kali source to app port.
- [ ] Clone source matches frozen manifest or approved lab-specific change list; root `.env`, production archive and runtime storage excluded.
- [ ] Lab environment uses unique secrets and `chimera_lab` only; no production/development/test DB host or credential; runtime app account non-root.
- [ ] New isolated DB has 11 tables, synthetic reference data, fresh synthetic accounts and no real data; document fixture is harmless and owned.
- [ ] PHP extensions, Apache rewrite, private storage, writable permissions and normal workflows checked; differences from InfinityFree (notably HTTP/TLS) documented.
- [ ] Global LAB switch false and modules REMEDIATED at known-good snapshot; enablement/rollback plan separately approved.
- [ ] Evidence directory, backup/snapshot, reset target names, stop conditions and authorization are recorded.
- [ ] Production freeze fingerprint still passes and no production request/change occurred during lab preparation.

If any item is unknown, **LAB READINESS = BLOCKED**. This proposal itself does not satisfy readiness.

## 9. Open decisions and approval request

1. Confirm the VMware VMnet/network mode and whether a dedicated Linux target VM can be added on the same **host-only** segment as Kali. Do not assign a target IP yet.
2. Confirm target VM OS/resources and whether Docker Engine + Compose are available/acceptable; otherwise select the dedicated-VM direct-install fallback.
3. Confirm whether temporary network access for package/image staging is acceptable before the test window and how it will be removed and verified.
4. Approve the planned app listener port and firewall source restriction after IP discovery, with no DB port publication.
5. Approve the synthetic identity set (two USERs plus one Security Admin), a tiny harmless document, and secret-provisioning method. No passwords belong in chat or repository.
6. Decide whether initial HTTP lab mode is sufficient or private TLS parity is needed for session/security-header comparisons; neither decision changes production.
7. Approve Phase 2 creation of the listed `lab/` files and detailed runbook. **No deployment, container start, schema import, account creation, LAB activation or pentest tool execution is authorized by this proposal.**
