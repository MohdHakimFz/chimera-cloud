# PROJECT CHIMERA - Track A Scanning Kali Linux Guide

**Planning manual only. Do not execute a test merely because its instructions appear here.** Read the current [Scope and ROE](../PENTEST_SCOPE_AND_ROE.md), [Methodology](../PENTEST_METHODOLOGY.md), [Track A Scanning Plan](../TRACK_A_SCANNING_PLAN.md), and [Target Freeze](../PRE_PENTEST_TARGET_FREEZE.md) first. Track A Reconnaissance is operator-reported complete; the Scanning results below are **not yet observed**. Production target: `https://projectchimera.infinityfreeapp.com/` only. InfinityFree infrastructure and other customers are out of scope. Production LAB stays disabled.

## One-test operating rule

**RUN ONE TEST -> SAVE EVIDENCE -> STOP -> ANALYZE/CLASSIFY -> APPROVE NEXT TEST.** Do not run all sections in order without a guide checkpoint. The guide must explicitly name the current test and authorized role before each operator action. At present the first candidate is **A-SCAN-001 only**. No A-SCAN command or production request was run to write this manual.

Use Firefox on Kali for these application-level tests. Terminal is not required for the seven proposed actions. Open Firefox from the Kali panel or Applications menu; type only the exact CHIMERA origin or an approved same-origin path reached through visible navigation. Firefox Developer Tools can be opened with `F12`; **Inspector** shows the page's form structure, **Network** shows browser-generated requests, and **Storage** shows cookie attributes. Do not copy raw request/response bodies, password fields, cookies or hidden token values. Do not press Reload to improve a screenshot; it creates another request. Close DevTools or a tab if it begins exposing sensitive material.

Initial Kali-local evidence directory: `~/chimera-pentest-evidence/`. It is distinct from the Windows project directory `E:\My Project\Chimera\evidence\pentest\track-a\scanning\`; do not assume a VMware shared-folder path. If needed, create the Kali-local directory with `mkdir -p ~/chimera-pentest-evidence` (local-only; `mkdir` creates a folder, `-p` tolerates an existing one, and `~` is your Kali home). Write concise text notes in a local editor; transfer only sanitized evidence later. Every test uses a matching `A-SCAN-NNN_short-name.txt` and optional `.png`. Do not make placeholder result files.

At every test, record timestamp, observed same-origin path, role, method, request count, expected versus observed behavior, screenshot/text reference, and cleanup status. Crop/redact screenshots **before** sharing. Never preserve passwords, `.env`, DB secrets, cookies/session values, CSRF values, `source_ip`, `source_hash`, private `storage_name`, honeytoken secrets, other users' documents or unnecessary PII. If a real secret, other customer's data, provider path, repeated 5xx, instability or abuse control appears: **stop immediately** and send only a minimal sanitized description.

No Nmap, Nikto, Nuclei, ffuf, Gobuster, DirBuster, sqlmap, Hydra, Medusa, Metasploit, Burp Active Scanner, automated crawler, brute force, fuzzing, provider-IP request, direct DB-host request, decoy/LAB request or high concurrency is part of this guide. The DNS IP from Recon is evidence only. No `curl` is necessary for this manual; do not substitute it on your own.

## A-SCAN-001 - Guest authentication-form surface

**What and why:** map the normal login/registration inputs and form methods. This is systematic input-surface Scanning, not a password test. It is safe because only normal public pages are viewed; no form is submitted.

**Before:** wait until the guide approves A-SCAN-001. Use a guest Firefox context; sign out first if already signed in. Do not use saved autofill in screenshots.

**Exact approved action:** from the CHIMERA public navigation, open **Sign in**, then **Create account**, once each. On each page press `F12`, choose Inspector, select the form and note its action, method, visible input labels/types, length hints and whether a hidden field named `_token` exists. Record the **name only**, not its value. Do not submit either form. If navigation differs, stop and report it instead of guessing paths.

**Normal / abnormal:** normally the forms render and advertise POST actions and labeled fields. A missing page, unexpected off-origin action, visible secret or disclosure is a review item—not automatically a vulnerability. Hidden-token presence does not prove server enforcement.

**Evidence:** write `A-SCAN-001_auth-forms.txt`; optional `A-SCAN-001_auth-forms.png` showing safe form labels/action/method. Crop hidden values, password autofill, browser identity and unrelated tabs.

**STOP HERE. Send the text/optional screenshot for analysis. Do not execute A-SCAN-002.**

## A-SCAN-002 - Controlled session and cookie attributes

**What and why:** observe ordinary guest-to-USER-to-guest behavior and cookie *attributes*. This is session-surface mapping, not session theft or bypass. It is safe when one existing authorized synthetic USER is used for one normal login/logout.

**Before:** wait for A-SCAN-001 review and separate approval. Have the authorized account credentials privately; never send them to the guide. Start a clean Firefox context. If no approved account is available, stop; do not register one for convenience.

**Exact approved action:** log in once through the normal CHIMERA form; confirm the USER dashboard. Press `F12`, open Storage, select Cookies for the CHIMERA origin. Inspect only whether Secure, HttpOnly, SameSite, domain, path and expiry/session attributes are present. **Do not copy or screenshot the cookie table or values.** Close DevTools. Use the normal Logout control once. If the logout flow itself does not establish protected-route behavior and the guide authorized a check, request the known `/dashboard` page once as guest and record the redirect/message; otherwise omit that extra request.

**Normal / abnormal:** expected is successful normal login, USER role, and logout that leaves the protected view unavailable. Cookie attributes require context before judging security. A failed login is not a reason to retry repeatedly; stop and report the issue without the password.

**Evidence:** `A-SCAN-002_session-attributes.txt`, listing attribute names and yes/no/not-visible only; optional cropped `A-SCAN-002_session-attributes.png` of safe login/logout UI, **never** the cookie values. Normal auth/logout telemetry and session state may change; no business fixture is created.

**STOP HERE. Send sanitized observations for analysis. Do not execute A-SCAN-003.**

## A-SCAN-003 - USER input and CSRF surface inventory

**What and why:** inventory the USER's own profile/document forms and their CSRF field presence. This is form/control mapping, not a CSRF bypass test. It uses normal page views only.

**Before:** wait for A-SCAN-002 review and approval; sign in as an authorized synthetic USER. Do not create a document just to find a delete form.

**Exact approved action:** use visible navigation to open Profile and Documents, once each. In Firefox Inspector, record each form's action/method, labeled inputs, upload accept/size hints, disabled fields and the presence of `_token` by **field name only**. Inspect the normal logout form if visible. If a USER-owned synthetic document detail/delete form is already available through legitimate navigation, include its method/token presence; otherwise write **not observed**. Do not submit any form or copy values.

**Normal / abnormal:** expected is POST for state-changing forms with a CSRF field. A field's presence is a surface observation, not proof of server-side rejection. If a path or value looks sensitive, stop and ask before recording.

**Evidence:** `A-SCAN-003_user-forms-csrf.txt`; optional cropped `A-SCAN-003_user-forms-csrf.png` with action/method/field names only. Redact profile values, token values, filenames unrelated to the test and account PII. No business data should change.

**STOP HERE. Send the form inventory for analysis. Do not execute A-SCAN-004.**

## A-SCAN-004 - Role-aware navigation and SOC surface

**What and why:** map surfaces normally presented to USER and Security Admin. This is role-aware attack-surface enumeration, **not** an authorization-bypass attempt. It is safe when each role uses only its own approved account and visible navigation.

**Before:** wait for A-SCAN-003 review and approval. Have separate authorized USER and Security Admin accounts. Never share credentials. If Security Admin access is unavailable, mark that branch not tested.

**Exact approved action:** in the USER session note visible navigation and normal dashboard page names. Log out. In a separate Security Admin session, follow visible links to Security Overview, Threat Sessions, Events, Analytics and Deployment Readiness as needed to identify the surfaces, no more than one normal visit per selected page. If the LAB management presentation is visible, record its displayed status only; do not click a state-change control. Do **not** enter `/security` as USER for this test or try hidden routes.

**Normal / abnormal:** expected is different role-appropriate navigation and readable SOC views. A hidden link does not prove server-side denial. Unexpected sensitive data, source-correlation values or honeytoken material means stop and redact.

**Evidence:** `A-SCAN-004_role-surfaces.txt` containing role, observed page/link and discovery method; optional cropped `A-SCAN-004_role-surfaces.png`. Redact names/emails, event detail, source identifiers, tokens and cookies. Log out when finished. Normal session/telemetry changes may occur; no business fixture is planned.

**STOP HERE. Send the role map for analysis. Do not execute A-SCAN-005.**

## A-SCAN-005 - Owned document/upload/download surface

**What and why:** map a legitimate USER document's upload, detail, object reference, application download and owner cleanup. This is not an IDOR test or direct-storage probe. It is safe only with **separate approval** for one tiny synthetic `.txt` document and immediate normal cleanup.

**Before:** wait for A-SCAN-004 review and explicit A-SCAN-005 fixture approval. Use an authorized synthetic USER. Prepare one small harmless text file with a unique non-secret marker in a local text editor; no private or personal content. Know how to use the normal Delete form. If cleanup is uncertain, postpone the test.

**Exact approved action:** visit Documents through normal navigation; note displayed allowed formats and size limit. Upload the one `.txt` file once using the normal browser form. Observe whether it appears in the owner's listing and detail page; note a synthetic numeric document ID only if visible in the URL. Use the normal Download action once, then compare the downloaded harmless bytes with your local fixture. Use the normal owner Delete action once, and check that the fixture disappears from the listing. Do not inspect a storage URL or internal filename. If any step fails, **stop** and retain the state for guided cleanup; no SQL/File Manager improvisation.

**Normal / abnormal:** expected is one successful owner lifecycle with application-mediated download and normal deletion. A visible ID is not itself a vulnerability. A mismatch, leaked private path or failed cleanup needs evidence review.

**Evidence:** `A-SCAN-005_document-surface.txt`; optional cropped `A-SCAN-005_document-surface.png` showing only the synthetic fixture and safe metadata. Do not include `storage_name`, private path/URL, unrelated documents, cookies, CSRF value or private file contents. This test creates and deletes **one synthetic document** and may create normal activity/telemetry records.

**STOP HERE. Report fixture cleanup state and evidence. Do not execute A-SCAN-006.**

## A-SCAN-006 - Passive browser request/API inventory

**What and why:** observe same-origin requests Firefox naturally makes for a normal page. This is passive application-request mapping, not endpoint enumeration. It is safe because no request is replayed or guessed.

**Before:** wait for A-SCAN-005 review and approval. Select one role-appropriate normal page already approved by the guide. If no API request appears, that is a valid observation.

**Exact approved action:** press `F12`, open Network, then navigate **once** to the selected normal CHIMERA page. Read only request **method, same-origin path, status and initiator/page**. Note any naturally loaded API route. Do not open request bodies, cookie headers or response data containing account/security details. Do not replay a request, edit its method, type a local-source-known `/api/...` path, or refresh for more data.

**Normal / abnormal:** expected is a short ordinary request list; it may contain no API call. A source-code route not seen in the browser remains **not externally observed / not tested**. An off-origin or unexpected sensitive request is a stop-and-review item.

**Evidence:** `A-SCAN-006_passive-requests.txt`; optional cropped `A-SCAN-006_passive-requests.png` showing only method/path/status columns. Redact query secrets, cookie/authorization headers, payloads, source identifiers and private data. Observation only; no fixture cleanup.

**STOP HERE. Send the passive request list for analysis. Do not execute A-SCAN-007.**

## A-SCAN-007 - Benign own-profile validation boundary

**What and why:** observe one ordinary server-side validation message for an invalid display name on your **own synthetic USER account**. This is a bounded validation-control check, not fuzzing or gaining access. It requires separate approval because it sends one POST and may create a security event.

**Before:** wait for A-SCAN-006 review and **explicit A-SCAN-007 approval**. Use a synthetic USER only. Privately note the current displayed name to confirm it stays unchanged; do not put it in evidence. Use the normal Profile form with its existing browser-managed CSRF field. If you cannot verify the original name or test account, stop.

**Exact approved action:** on your own Profile page, replace Full name with the single character `X`; submit the normal form **once**. Observe the response/redirect and safe validation message. Confirm the original profile name remains unchanged. Do not vary the input, tamper with the token, repeat the request, or try another account.

**Normal / abnormal:** expected is a validation error and no business-profile change; local implementation indicates one `INVALID_REQUEST` security event may be recorded. No PHP warning, SQL text, stack trace or filesystem path should appear. If the name changes or an error appears, stop and seek guided review rather than testing again.

**Evidence:** `A-SCAN-007_profile-validation.txt`; optional cropped `A-SCAN-007_profile-validation.png` showing the safe error message but no personal name, token or account email. Record whether business data stayed unchanged and whether cleanup is needed; do not seek extra SOC telemetry just to populate evidence.

**STOP HERE. Send the single result for analysis. Do not begin Gaining Access or Track B.**

## Academic evidence and diagram reminder

The report can use at least three different Scanning methods: auth/session observation (001-002), form/CSRF and validation mapping (003/007), role/document surface mapping (004/005), and passive request observation (006). For each *executed* method, write Implementation -> Result -> Analysis/justification -> Countermeasure if warranted -> Insight. Do not manufacture results for skipped tests. A logical diagram may show Kali -> HTTPS -> CHIMERA origin -> application-controlled backend/data layer, with the InfinityFree shared-hosting boundary marked and provider systems, other virtual hosts/customers and direct database-host scans explicitly outside scope. It is not a scanned network topology.

The following belong only in a separately approved isolated Track B plan: port/service scanning, Nikto, Nuclei, directory fuzzing, Burp active scanning, sqlmap, intentional LAB SQLi/IDOR/XSS modules, and controlled exploitation. The production LAB remains disabled. Stop at the end of the current approved test and return evidence before any next phase.
