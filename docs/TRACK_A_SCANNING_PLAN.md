# PROJECT CHIMERA - Track A live-production scanning plan

**Status: PLAN ONLY. No A-SCAN test has been executed by creating this document.** Track A Reconnaissance A-REC-001 through A-REC-010 is operator-reported complete with no confirmed vulnerability in that bounded phase; that does not establish that CHIMERA is vulnerability-free. The frozen target remains `https://projectchimera.infinityfreeapp.com/`, LAB disabled. [Scope and ROE](PENTEST_SCOPE_AND_ROE.md), [Methodology](PENTEST_METHODOLOGY.md), [Recon Plan](TRACK_A_RECON_PLAN.md), [Recon Kali Guide](kali-guides/TRACK_A_RECON_KALI_GUIDE.md), and [Freeze](PRE_PENTEST_TARGET_FREEZE.md) remain authoritative. Historical statements in these documents that testing had *not yet started* describe their original publication time; this plan records the later operator-reported Recon completion without rewriting historical evidence.

## Scanning definition and execution gate

Here, Scanning means a systematic **manual, low-volume application-surface and control-boundary inventory**, not network or automated vulnerability scanning. Recon already covered public DNS, TLS, root HTTP, headers, source, JavaScript, metadata and public routes. This phase moves to form semantics, authenticated state, role-specific navigation, document workflow, passively observed requests and one benign validation boundary. It does not attempt bypass, cross-user access, payload fuzzing or exploitation; those require a later Gaining Access plan or Track B.

**One A-SCAN test at a time:** guide selects one ID -> operator executes only it -> saves sanitized evidence -> stops -> guide analyzes/classifies and checks scope -> next ID requires explicit approval. Tests below are future procedures, not instructions to run now. Before an authenticated test, the operator must have an authorized synthetic account and a clean browser context. Never request or record credentials. Normal authentication, logout and document activity may create expected application events. A-SCAN-007 intentionally creates one `INVALID_REQUEST` security event if executed; this is security-evidence mutation, not authorized business-data mutation.

Use only the exact origin. Do not use the DNS answer as a target. No provider-IP or database-host probing, other tenants, broad crawling, brute force, scanning, high concurrency, destructive input, decoys, honeytokens, or LAB interaction. Do not use Nmap, Nikto, Nuclei, ffuf, Gobuster, DirBuster, sqlmap, Hydra, Medusa, Metasploit or Burp Active Scanner on production. Stop for scope ambiguity, another customer's data, unexpected personal data, instability/repeated 5xx, provider abuse controls, or sufficient proof. Do not follow off-origin redirects. No actual classification or observed result is pre-filled.

## Source-informed design, not attacker-discovered evidence

Local `routes/web.php`, `docs/ROUTE_SECURITY_MATRIX.md`, `AuthController`, `DocumentController`, `ApiController`, `ProfileController`, `UploadValidator`, `VerifyCsrf`, and the corresponding PHP views were reviewed to keep future actions bounded. They show guest login/register POSTs, authenticated logout/profile/documents POSTs, owner-scoped document GET/download/delete, USER JSON routes, and Security Admin read pages/API routes. Local `AuthController` records normal login/logout events; invalid login can score, so **no failed-login trial is planned**. Local `ProfileController` rejects a one-character name before update and records `INVALID_REQUEST`; A-SCAN-007 is deliberately limited to that single benign validation if separately approved. `DocumentController` records normal upload/download/delete activity, and its upload form displays approved formats and size.

Those facts are **developer design inputs**, not claims that an external pentester observed these routes or controls. An A-SCAN result may cite a route/field only if the operator actually sees it through normal navigation, source already observed in Recon, or a naturally loaded same-origin browser request. A source-known API endpoint that is not naturally observed remains **NOT EXTERNALLY OBSERVED / NOT TESTED**; never request it merely because it exists in source. Do not open decoy or LAB routes, including when they appear in local route definitions.

## Ordered tests and request/data budget

| ID | Test | Method | Auth | Synthetic business data | New activity |
|---|---|---|---|---|---|
| A-SCAN-001 | Guest authentication-form surface | Public form/method inventory | No | No | Two normal page visits at most |
| A-SCAN-002 | Controlled session and cookie attributes | Normal login/logout + browser cookie-attribute observation | USER | No | One login and logout; normal session/events |
| A-SCAN-003 | USER input and CSRF surface inventory | Authenticated form inspection | USER | No | Normal page visits only |
| A-SCAN-004 | Role-aware navigation and SOC surface | Normal USER and Security Admin page/navigation comparison | Both | No | Normal pages only; no forced boundary request |
| A-SCAN-005 | Owned document/upload/download surface | One harmless owner fixture lifecycle | USER | **Yes: one tiny text document** | Upload, download and owner delete; cleanup required |
| A-SCAN-006 | Passive browser request/API inventory | DevTools Network during already-approved normal pages | USER and/or Security Admin | No | No extra endpoint requests |
| A-SCAN-007 | Benign profile validation boundary | One invalid own-profile submission | USER | No intended business change | One POST and redirect; one expected security event |

If a prerequisite is absent, skip or pause that test rather than creating new accounts or making guessed requests. Every page visit has an ordinary browser request cost; do not refresh for a screenshot. A-SCAN-005 and A-SCAN-007 are separately gated despite appearing in the plan.

### A-SCAN-001 - Guest authentication-form surface

- **Objective / why Scanning:** inventory the *actual* login and registration form methods, field names, input constraints, hidden CSRF field presence and navigation as application input surfaces. Recon saw public pages; this step systematically maps controls, without testing bypass or invalid credentials.
- **Preconditions / target / tool:** guest Firefox context; only `/login` and `/register` reached through normal public navigation on the exact CHIMERA origin; Firefox page/DevTools Elements. If a link was not naturally observed, ask the guide before using a source-known path.
- **Exact safe procedure:** visit each page once; inspect the form's displayed action/method, visible labels, type/length attributes and presence of a hidden `_token` field. Record the field *name*, never its value. Submit nothing.
- **Expected normal behavior / evidence:** rendered forms with POST actions and labels; record what is actually visible, or inability to inspect. `A-SCAN-001_auth-forms.txt`; optional redacted `A-SCAN-001_auth-forms.png`. Do not capture passwords, token values, autofill or browser profile PII.
- **Stop / classification / academic value:** stop after both form inventories or any secret exposure. Usually INFORMATIONAL OBSERVATION or SECURITY CONTROL SUCCESS if supported; unexpected exposure is reviewed, not pre-labeled. Method: manual form/input enumeration.
- **Mutation / cleanup / later GA:** no submission, no business mutation, no cleanup. Later GA may separately assess auth validation or CSRF resistance; this test does not.

### A-SCAN-002 - Controlled session and cookie attributes

- **Objective / why Scanning:** map normal transition guest -> USER -> guest and observe *attributes*, not values, of browser-managed CHIMERA cookies. Recon was unauthenticated; this checks the authenticated session surface without guessing credentials or forcing access.
- **Preconditions / target / tool:** existing authorized synthetic USER and privately held credentials; `/login`, `/dashboard`, normal `/logout` form on the CHIMERA origin; Firefox UI and DevTools Storage/Cookies. No account creation or failed-password attempt.
- **Exact safe procedure:** in a clean context, log in once normally; verify dashboard/USER role. In Firefox Storage inspect only cookie **attribute labels**: Secure, HttpOnly, SameSite, domain, path, expiry/session. Record presence/absence without values or screenshots of the cookie table. Use the normal Logout button once; verify a protected page redirects to sign-in via normal navigation only if needed and not already shown by the logout flow.
- **Expected normal behavior / evidence:** normal authenticated page then logout; attribute-only note `A-SCAN-002_session-attributes.txt`, optional cropped UI `A-SCAN-002_session-attributes.png` without cookies or identity detail. Never capture credential, cookie, session ID, CSRF token or password-manager popup.
- **Stop / classification / academic value:** stop on normal logout or unexpected authentication behavior. Candidate SECURITY CONTROL SUCCESS/INFORMATIONAL OBSERVATION/INCONCLUSIVE; a missing attribute requires context before vulnerability classification. Method: session/cookie control inspection.
- **Mutation / cleanup / later GA:** no durable business data; session and normal auth telemetry change. Logout is cleanup. Later GA may test session weaknesses only under a separate plan.

### A-SCAN-003 - USER input and CSRF surface inventory

- **Objective / why Scanning:** map authenticated USER forms and naturally visible input fields, especially state-changing method/action and `_token` presence. This inventories CSRF boundaries but does not send missing/invalid tokens.
- **Preconditions / target / tool:** authorized USER session; normal navigation to `/profile` and `/documents`, plus visible logout form; Firefox Elements. A delete form is inspected only if a USER-owned synthetic document already exists from an approved test—do not create one for this inventory.
- **Exact safe procedure:** view each page once; record labels, form actions/methods, file accept/size hints, disabled fields, and hidden `_token` *presence*. If the document detail/delete form is unavailable, mark it not observed. Do not submit, alter values or copy hidden field contents.
- **Expected normal behavior / evidence:** inventory `A-SCAN-003_user-forms-csrf.txt` with observed vs not observed; optional cropped `A-SCAN-003_user-forms-csrf.png` showing field structure but no values. No passwords, tokens, account PII, storage names or file paths.
- **Stop / classification / academic value:** stop after the visible form inventory; possible INFORMATIONAL OBSERVATION or supported SECURITY CONTROL SUCCESS. Mere hidden-token presence does **not** prove server-side CSRF enforcement. Method: authenticated input/CSRF surface mapping.
- **Mutation / cleanup / later GA:** read-only browser observation, none. Later GA may separately test CSRF enforcement after approval.

### A-SCAN-004 - Role-aware navigation and SOC surface

- **Objective / why Scanning:** identify what normal USER and Security Admin roles can reach through their own visible navigation, without treating hidden links as authorization proof.
- **Preconditions / target / tool:** two existing authorized test roles, sequential sessions, no shared credential exposure; normal `/dashboard` and `/security` reached through role-appropriate navigation; Firefox. If the role or link is unavailable, mark that branch not tested.
- **Exact safe procedure:** inspect USER navigation and its normal landing page; log out; independently authenticate Security Admin and inspect its normal Security Overview, Threat Sessions, Events, Analytics and Deployment Readiness navigation/pages at most once each as useful. Keep LAB presentation read-only if visible; never operate a state-change control. Record only page names and safe presentation fields. No forced `/security` request while USER in this Scanning test.
- **Expected normal behavior / evidence:** role-specific route/page table in `A-SCAN-004_role-surfaces.txt`; optional cropped `A-SCAN-004_role-surfaces.png`. Redact user identities, security-event details, source identifiers/hashes, honeytoken values, tokens and cookies.
- **Stop / classification / academic value:** stop after minimal role map or any sensitive disclosure. INFORMATIONAL OBSERVATION or supported SECURITY CONTROL SUCCESS, not proof against direct authorization bypass. Method: manual role-aware surface mapping.
- **Mutation / cleanup / later GA:** no business mutation; normal login/logout telemetry/session changes. Log out both sessions. Later GA may perform bounded authorization tests with separate approval.

### A-SCAN-005 - Owned document/upload/download surface

- **Objective / why Scanning:** identify the legitimate upload restrictions, object-ID appearance, owner detail/download path and application-mediated storage behavior—not test another user's document or direct storage URLs.
- **Preconditions / target / tool:** authorized synthetic USER, explicit separate approval for one production fixture, cleanup ability, tiny harmless `.txt` with unique *non-secret* marker; normal `/documents` UI in Firefox. No existing private user document is used.
- **Exact safe procedure:** read the displayed allowlist/size hint; create one tiny local text fixture; upload once via the normal form and valid browser CSRF context; observe its listing/detail URL and safe displayed metadata; download once via the normal owner action and compare bytes locally; delete once using the normal owner form; verify it disappears. Record only the synthetic numeric object ID if needed, never internal storage name/path. If upload, download or delete deviates, stop and preserve the fixture state for guided cleanup instead of improvising SQL/File Manager actions.
- **Expected normal behavior / evidence:** one owner-controlled lifecycle, `A-SCAN-005_document-surface.txt`; optional redacted `A-SCAN-005_document-surface.png`. Do not preserve private contents beyond the harmless marker, unrelated listing entries, checksum if unnecessary, storage_name, paths, cookies or CSRF values.
- **Stop / classification / academic value:** stop after deletion and a normal listing check, or immediately on unexpected behavior. Supported SECURITY CONTROL SUCCESS/INFORMATIONAL OBSERVATION/INCONCLUSIVE; an observed defect needs review. Method: bounded document and object-reference surface mapping.
- **Mutation / cleanup / later GA:** **creates and deletes one synthetic document**, plus normal activity/telemetry records. Verify UI cleanup. Later GA may separately test ownership/IDOR; no cross-user request here.

### A-SCAN-006 - Passive browser request/API inventory

- **Objective / why Scanning:** identify same-origin request methods and API calls **naturally generated** while using approved normal pages; source-known but externally unseen API routes are not tested.
- **Preconditions / target / tool:** an already-approved normal USER or Security Admin page visit; Firefox DevTools Network, opened before that visit if practical. Disable neither security controls nor browser protections.
- **Exact safe procedure:** observe the Network list for only that normal visit. Record method, same-origin path, status and initiating page for relevant application requests. If no API call appears, record **no API observed**. Do not replay, edit or send a request; do not open a source-known `/api/...` URL merely because the local repository lists it.
- **Expected normal behavior / evidence:** a small request table or a justified none-observed result in `A-SCAN-006_passive-requests.txt`; optional cropped `A-SCAN-006_passive-requests.png`. Do not capture Headers/Cookies/Request Body tabs, tokens, source identifiers, event payloads or sensitive query strings.
- **Stop / classification / academic value:** stop after the one approved page load; INFORMATIONAL OBSERVATION/INCONCLUSIVE unless an actual issue is supported. Method: passive browser request/API surface observation.
- **Mutation / cleanup / later GA:** observation only; normal GET may have ordinary application telemetry, but no deliberate business mutation. No cleanup. Any API authorization test belongs to later GA.

### A-SCAN-007 - Benign own-profile validation boundary

- **Objective / why Scanning:** observe one normal server-side validation/error response without payload fuzzing, malformed protocol or a credential attack. This checks how a known form handles an invalid *own-profile* display name.
- **Preconditions / target / tool:** existing synthetic USER, explicit separate approval for one validation POST, current profile name privately noted for comparison, Firefox normal `/profile` form. Do not use a real person's account.
- **Exact safe procedure:** enter a single-character harmless name (for example `X`) in the USER's own Full name field and submit **once through the existing form with its browser-managed valid CSRF token**. Observe the displayed validation feedback and that the prior profile name remains unchanged. Do not repeat with variants. The source indicates this should reject before `User::updateName` and record one `INVALID_REQUEST`; the live result remains to be observed.
- **Expected normal behavior / evidence:** safe validation message, no profile-name change, no warning/stack trace/path/SQL exposure. Record status/visible message without account PII in `A-SCAN-007_profile-validation.txt`; optional cropped `A-SCAN-007_profile-validation.png`.
- **Stop / classification / academic value:** stop immediately after one response and own-profile comparison. SECURITY CONTROL SUCCESS/INFORMATIONAL OBSERVATION/INCONCLUSIVE as evidence warrants; classify an actual mutation or disclosure only after review. Method: one bounded normal validation-boundary check.
- **Mutation / cleanup / later GA:** **no intended business-data mutation**, but one `INVALID_REQUEST` security-evidence event may be created. If a name unexpectedly changes, stop and seek guided recovery; do not perform extra requests reflexively. Later GA may test input weaknesses under a separate plan.

## Evidence, classification and academic reporting

Store only real execution evidence under `evidence/pentest/track-a/scanning/`, first in Kali if no Windows share is available. Use `A-SCAN-001_auth-forms.txt` / matching `.png`, and the stems in each test above. Each record includes test ID, operator timestamp, exact same-origin target, authorized role, objective, method, request count, expected and observed behavior, status where visible, result classification, impact/uncertainty, cleanup, and evidence references. Do not invent results or paste full browser storage, request bodies, raw account data or private documents. Screenshots are cropped/redacted **before** academic use.

Permitted outcome labels are **CONFIRMED VULNERABILITY**, **SECURITY CONTROL SUCCESS**, **INFORMATIONAL OBSERVATION**, **PROVIDER/HOSTING LIMITATION**, **OUT-OF-SCOPE OBSERVATION**, and **INCONCLUSIVE**. A visible field, route, cookie name or technology is not a vulnerability. A suspected defect is recorded with minimal proof and reviewed before any further reproduction. The academic Scanning section should explain why manual bounded application scanning replaced production network scanning, then use at least three distinct methods: (1) auth/session and cookie mapping, A-SCAN-001/002; (2) CSRF/input and validation boundary mapping, A-SCAN-003/007; (3) role and document-object surface mapping, A-SCAN-004/005; optionally (4) passive browser/API inventory, A-SCAN-006. For each method, document implementation, actual result, analysis/justification, proportionate countermeasure if needed, and insight. No result is filled in advance.

## Logical network/system diagram for the report

Use a **logical scope diagram based on already-known architecture**, not a provider-network discovery claim:

```text
Kali Linux operator
      |  bounded HTTPS to one application origin
      v
+------------------------------------------------------------+
| InfinityFree shared-hosting boundary (provider OUT OF SCOPE)|
|  CHIMERA public origin (application IN SCOPE)               |
|             | application-controlled requests               |
|             v                                               |
|  CHIMERA backend / data layer (not directly scanned)        |
+------------------------------------------------------------+
Other customers / virtual hosts / provider control systems: OUT OF SCOPE
```

This is an architectural/scope illustration, not evidence of discovered provider topology. The database host is not a direct target, and the DNS IP from Recon is never scanned.

## Techniques Deferred to Track B

| Not permitted for this production plan | Later isolated-clone venue |
|---|---|
| Port/service scanning (including Nmap), provider-IP discovery | Track B only, against its isolated host |
| Nikto, Nuclei, directory fuzzing with ffuf/Gobuster/DirBuster | Track B only |
| Burp active scanning, high-volume crawling/fuzzing | Track B only |
| sqlmap automation and deeper injection exercises | Track B only |
| Intentional SQLi, IDOR and XSS LAB modules | Track B only; production LAB stays disabled |
| Controlled exploitation and high-impact techniques | Separate approved Track B plan only |

Neither this mapping nor the beginner guide executes or authorizes Track B. Track A Gaining Access also requires a separate, tightly scoped future plan; do not advance to it automatically.

## Next control point

First manual test, when separately authorized: **A-SCAN-001 - Guest authentication-form surface**. Execute only that test, return sanitized evidence, classify it, and approve the next step separately. This planning run made no production request, changed no frozen runtime file, and created no result evidence.
