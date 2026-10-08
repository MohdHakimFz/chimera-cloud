# Track A — live CHIMERA reconnaissance plan

**Status: PLANNING ONLY. No reconnaissance request has been sent.**

Target application: `https://projectchimera.infinityfreeapp.com`  
Target boundary: CHIMERA application only. InfinityFree infrastructure, provider IPs, control panel, database host, neighboring virtual hosts and other customers are out of scope.  
Frozen reference: [PRE_PENTEST_TARGET_FREEZE.md](PRE_PENTEST_TARGET_FREEZE.md), [PENTEST_SCOPE_AND_ROE.md](PENTEST_SCOPE_AND_ROE.md), and [PENTEST_METHODOLOGY.md](PENTEST_METHODOLOGY.md). These current documents govern over historical plans.  
Freeze: `2026-10-08T02:17:44+08:00`; 128 production-relevant files; manifest SHA-256 `f2fc02bc3ce1412b2c746c53f1384722e6507098bc29279a620cba4d8a6a134c`. Production LAB: `VULNERABILITY_LAB_ENABLED=false`.

## Operator rhythm and safety gate

This is a beginner-guided, one-step-at-a-time workflow:

**Guide selects one test → gives one current instruction → operator executes only that instruction → sends sanitized output/screenshot → guide analyzes → evidence is saved → result is classified → scope and stop conditions are checked → only then may another step be selected.**

Do not copy and run this document as a command list. Do not automate the reconnaissance phase. Every test below ends at a deliberate stop point. Commands shown are **future candidates, not instructions to execute now**; the guide must confirm the exact current step before the operator uses one. No high concurrency, fuzzing, brute force, port scan, vulnerability scanner, exploit, decoy or honeytoken interaction is part of this plan. Kali will be used by the operator only after separate execution authorization.

Do not use production Nmap, Nikto, Nuclei, ffuf, Gobuster, Dirbuster, sqlmap, Hydra, Medusa, Metasploit or Burp Active Scanner. Do not follow redirects or discoveries into provider infrastructure. Prefer reusing earlier output over making another request.

## Ordered tests

| Order | ID | Name | Planned new network activity |
|---:|---|---|---|
| 1 | A-REC-001 | Domain / DNS observation | One ordinary DNS lookup after approval |
| 2 | A-REC-002 | TLS / certificate observation | One normal TLS handshake or browser certificate view |
| 3 | A-REC-003 | Normal HTTP response | One normal root GET |
| 4 | A-REC-004 | Security header observation | Reuse A-REC-003 response |
| 5 | A-REC-005 | Technology fingerprinting | Reuse already delivered content |
| 6 | A-REC-006 | Public HTML / source inspection | View normal public page source |
| 7 | A-REC-007 | Public JavaScript / asset observation | Inspect one naturally referenced asset if useful |
| 8 | A-REC-008 | Standard public metadata | At most one justified `/robots.txt` request |
| 9 | A-REC-009 | Public route mapping | Reuse links, forms, redirects and asset references |
| 10 | A-REC-010 | Information disclosure review | Reuse accumulated Recon evidence |

### A-REC-001 — Domain / DNS observation

- **Objective:** observe ordinary public DNS resolution of `projectchimera.infinityfreeapp.com`.
- **Why:** distinguish the application hostname from the provider infrastructure it resolves to and establish the exact target identity.
- **Beginner explanation:** DNS maps a hostname to records. A returned address is an observation, not permission to probe that IP or its neighbors.
- **Tool / access:** Kali terminal; `dig` (or `nslookup` if `dig` is unavailable). Open a terminal only after the guide authorizes this test.
- **Exact future command:** `dig +time=5 +tries=1 projectchimera.infinityfreeapp.com A`. One query, no loop. The guide may select `nslookup` instead, but not both merely to duplicate evidence.
- **Command parts:** `dig` asks DNS; `+time=5` limits waiting; `+tries=1` prevents repeated attempts; the hostname is the only name; `A` asks for IPv4 records.
- **Expected output:** a DNS response or a clear lookup failure. Record the record type, response status and returned address only as public DNS evidence; do not assume a particular address.
- **Look for / avoid:** confirm the queried name and record type. Do not query provider ranges, brute-force subdomains, request zone transfer or connect directly to a returned IP.
- **Screenshot:** NO by default; machine-readable text is stronger. Take one redacted screenshot only if the response format is material to the report.
- **Screenshot content:** if needed, show the one hostname, query type and answer; no unrelated terminal history.
- **Evidence:** `evidence/pentest/track-a/reconnaissance/A-REC-001_dns.txt`; optional `A-REC-001_dns.png` in the same directory.
- **Stop point:** stop immediately after the one response, including a failure response.
- **Next action:** send sanitized output to the guide for scope interpretation and classification; do not start A-REC-002.

### A-REC-002 — TLS / certificate observation

- **Objective:** observe the normal HTTPS certificate for the CHIMERA hostname.
- **Why:** verify hostname coverage and record certificate issuer and validity without testing the provider's broader TLS estate.
- **Beginner explanation:** a certificate identifies the name covered by the HTTPS connection; viewing it does not test other hosts or cipher suites.
- **Tool / access:** browser certificate viewer is preferred for a beginner. Open the exact CHIMERA origin, select the browser's connection/certificate information, and inspect the certificate details. `openssl s_client` is an alternative only if the guide selects it.
- **Exact future command:** none for the browser method. If the browser cannot show the needed fields, the guide will provide one exact, hostname-scoped `openssl s_client` instruction at execution time.
- **Command parts:** not applicable to the browser method; the guide will explain any later terminal alternative before use.
- **Expected output:** subject/hostname coverage, issuer, validity dates and basic connection information, or an explicit inability to inspect them. Do not assume certificate values in advance.
- **Look for / avoid:** hostname match and validity. Do not enumerate ciphers, vary ports, connect to provider IPs or treat a provider-managed issuer as a defect by itself.
- **Screenshot:** YES if the browser certificate view clearly shows hostname and validity; otherwise retain concise text notes.
- **Screenshot content:** certificate identity and dates only, with unrelated browser/account details cropped or redacted.
- **Evidence:** `A-REC-002_tls.txt` and, if useful, `A-REC-002_tls.png` in the Track A reconnaissance directory.
- **Stop point:** stop after one normal certificate inspection.
- **Next action:** send sanitized certificate observations to the guide; do not start A-REC-003.

### A-REC-003 — Normal HTTP response

- **Objective:** observe the normal root response without changing application state.
- **Why:** establish status, redirect behavior, content type, cache behavior and ordinary server-visible metadata.
- **Beginner explanation:** this is one normal page request. A hosting challenge or redirect must be recorded as observed, not mistaken for CHIMERA output.
- **Tool / access:** Kali terminal with `curl`, or browser DevTools Network if the guide chooses the browser due to provider challenge behavior.
- **Exact future command:** `curl --max-time 15 --max-redirs 0 -sS -D - -o /dev/null https://projectchimera.infinityfreeapp.com/`. Run once only after authorization.
- **Command parts:** `--max-time 15` bounds waiting; `--max-redirs 0` prevents following redirects; `-sS` keeps errors visible; `-D -` prints response headers; `-o /dev/null` discards the body; the URL is the sole application root.
- **Expected output:** one status line and response headers, or a transport/challenge outcome. No particular status is invented.
- **Look for / avoid:** status, Location if present, content type, cache policy, server metadata. Do not follow an off-origin Location or retry repeatedly to bypass a challenge.
- **Screenshot:** NO by default; save sanitized text. A screenshot is optional if browser DevTools is used to distinguish a provider challenge.
- **Screenshot content:** the single request URL, status and relevant headers, without cookies.
- **Evidence:** `A-REC-003_http.txt`; optional `A-REC-003_http.png`.
- **Stop point:** stop after the one root response or clear error.
- **Next action:** send sanitized status and headers to the guide; do not start A-REC-004.

### A-REC-004 — Security header observation

- **Objective:** assess security-relevant headers already captured in A-REC-003.
- **Why:** identify deployed browser protections without another production request.
- **Beginner explanation:** headers are browser instructions. Their presence and policy structure matter more than a simple yes/no list.
- **Tool / access:** text editor or browser DevTools viewing the saved A-REC-003 response; no new network command.
- **Exact future command:** none; reuse A-REC-003 evidence.
- **Command parts:** not applicable.
- **Expected output:** an inventory of CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy and Cache-Control when observable. Absence is not automatically a vulnerability.
- **Look for / avoid:** policy values and whether the response is CHIMERA or a provider challenge. Do not copy `Set-Cookie` values into evidence.
- **Screenshot:** YES only if a relevant policy is clearer in DevTools than text; otherwise NO.
- **Screenshot content:** header names and non-secret policy values; cookie values redacted.
- **Evidence:** `A-REC-004_headers.txt`; optional `A-REC-004_headers.png`.
- **Stop point:** stop after classifying the already captured header set.
- **Next action:** send the header interpretation to the guide; do not start A-REC-005.

### A-REC-005 — Technology fingerprinting

- **Objective:** infer only technologies supported by normal responses and public assets.
- **Why:** describe the target stack and choose later application tests responsibly.
- **Beginner explanation:** a header or filename is a clue, not proof of a framework or version. Each claim needs an observed source.
- **Tool / access:** saved A-REC-003 response, normal browser page and naturally delivered asset names. No fingerprint scanner.
- **Exact future command:** none; reuse existing evidence.
- **Command parts:** not applicable.
- **Expected output:** a short table of observed clue, inference and confidence; unknowns remain unknown.
- **Look for / avoid:** PHP or asset conventions only where visible. Do not guess versions or probe hosting software to confirm them.
- **Screenshot:** NO unless a single visible clue is important and cannot be retained as text.
- **Screenshot content:** the specific public clue only.
- **Evidence:** `A-REC-005_technology.txt`; optional `A-REC-005_technology.png`.
- **Stop point:** stop when each inference has a citation to an already captured observation.
- **Next action:** send the evidence-backed table to the guide; do not start A-REC-006.

### A-REC-006 — Public HTML / source inspection

- **Objective:** inspect the normal public page source for forms, inputs, links, assets and accidental disclosure.
- **Why:** source visible to every visitor defines part of the legitimate attack surface.
- **Beginner explanation:** View Source shows delivered HTML; it does not reveal server-side PHP source. A hidden input may contain a live token and must not be copied into evidence.
- **Tool / access:** browser on the CHIMERA homepage; use the browser's View Page Source or Elements panel. The guide will choose the page and one inspection action.
- **Exact future command:** none for the browser method.
- **Command parts:** not applicable.
- **Expected output:** a concise inventory of public links, form actions/input names and referenced assets. Observed token values are redacted.
- **Look for / avoid:** comments, API references, debug strings, internal URLs, version disclosures, filesystem paths or secrets. Do not submit forms or request discovered protected routes yet.
- **Screenshot:** NO by default; YES only for an actual significant disclosure after redaction.
- **Screenshot content:** the relevant source fragment and public page identity, never token values.
- **Evidence:** `A-REC-006_html.txt`; optional `A-REC-006_html.png`.
- **Stop point:** stop after inspecting the one selected public page.
- **Next action:** send a sanitized inventory to the guide; do not start A-REC-007.

### A-REC-007 — Public JavaScript / asset observation

- **Objective:** inspect one asset naturally referenced by the selected CHIMERA public page.
- **Why:** client assets may reveal routes, validation rules or accidental secrets that are delivered to every visitor.
- **Beginner explanation:** only assets the page itself loads are in this step; a source-map hint is an observation, not a reason to crawl directories.
- **Tool / access:** browser DevTools Sources or Network panel. Open at most one directly referenced application JavaScript asset selected by the guide.
- **Exact future command:** none for the browser method. The exact asset URL must be taken from A-REC-006 rather than guessed in advance.
- **Command parts:** not applicable.
- **Expected output:** observed client-side route/API references, validation behavior and any relevant disclosure, or a clear statement that none was observed.
- **Look for / avoid:** hard-coded sensitive material, internal URLs, debug markers or source-map references. Do not request arbitrary assets or follow links outside the origin.
- **Screenshot:** NO by default; YES only for a significant, redacted finding.
- **Screenshot content:** the public asset identity and relevant non-secret fragment.
- **Evidence:** `A-REC-007_assets.txt`; optional `A-REC-007_assets.png`.
- **Stop point:** stop after one selected asset or a documented reason to skip it.
- **Next action:** send sanitized observations to the guide; do not start A-REC-008.

### A-REC-008 — Standard public metadata

- **Objective:** check one conventional application-level metadata path if the guide judges it useful.
- **Why:** `robots.txt` may document normal public crawling hints or return a safe 404; neither result proves a vulnerability.
- **Beginner explanation:** this is one known conventional filename, not a wordlist or directory search.
- **Tool / access:** browser address bar at the exact CHIMERA origin.
- **Exact future command:** none for the browser method; proposed single URL is `https://projectchimera.infinityfreeapp.com/robots.txt`.
- **Command parts:** not applicable.
- **Expected output:** content, redirect, safe 404 or provider response. Do not invent which will occur.
- **Look for / avoid:** application-owned public hints only. Do not request paths merely because a robots entry names them; do not enumerate hosting files.
- **Screenshot:** NO unless the response contains a significant non-secret observation.
- **Screenshot content:** URL, status and relevant text only.
- **Evidence:** `A-REC-008_metadata.txt`; optional `A-REC-008_metadata.png`.
- **Stop point:** stop after one response; skip the request if existing evidence makes it unnecessary.
- **Next action:** send sanitized result or skip rationale to the guide; do not start A-REC-009.

### A-REC-009 — Public route mapping

- **Objective:** make an attacker-view map of naturally disclosed CHIMERA routes.
- **Why:** later phases need a bounded list of known application paths and their apparent purpose.
- **Beginner explanation:** a visible link is not proof the destination is public. Record its source and classify conservatively.
- **Tool / access:** saved A-REC-003, A-REC-006, A-REC-007 and A-REC-008 evidence; no route crawler.
- **Exact future command:** none; reuse earlier output.
- **Command parts:** not applicable.
- **Expected output:** route, discovery source and provisional category: PUBLIC, AUTHENTICATION, REGISTRATION, PROTECTED, or UNKNOWN/NOT TESTED.
- **Look for / avoid:** navigation links, forms, normal redirects, public JS references. Do not brute-force routes or test authorization in this Recon step.
- **Screenshot:** NO by default; a single screenshot may support a particularly important visible route.
- **Screenshot content:** the source page and non-secret link/action, not a protected response.
- **Evidence:** `A-REC-009_routes.txt`; optional `A-REC-009_routes.png`.
- **Stop point:** stop once the map is traceable to natural discoveries; leave uncertain routes untested.
- **Next action:** send the route table to the guide; do not start A-REC-010.

### A-REC-010 — Information disclosure review

- **Objective:** review accumulated Recon evidence for accidental disclosure.
- **Why:** consolidating already observed outputs avoids deliberately generating production errors.
- **Beginner explanation:** a real disclosure needs evidence of sensitive content or useful internal detail, not merely a normal technology clue.
- **Tool / access:** local review of sanitized A-REC-001 through A-REC-009 records; no new production request.
- **Exact future command:** none.
- **Command parts:** not applicable.
- **Expected output:** a finding/control/observation decision for each meaningful disclosure candidate, with uncertainty recorded honestly.
- **Look for / avoid:** stack traces, SQL and filesystem details, configuration, credentials, tokens, internal hostnames, private storage information and source identifiers. Do not reproduce a possible secret in the report.
- **Screenshot:** NO new screenshot; refer to a prior redacted one if essential.
- **Screenshot content:** not applicable.
- **Evidence:** `A-REC-010_disclosure-review.txt`.
- **Stop point:** stop after the evidence review. Do not move into Scanning without a separate plan and approval.
- **Next action:** send the classified Recon summary to the guide for the next phase decision.

## Optional tests

No additional test is preapproved. If a concrete observation justifies another low-impact application/domain-scoped Recon step, the guide must mark it **OPTIONAL**, explain its value and request cost, and obtain a separate decision before an operator action. No wordlists, infrastructure probes or recursive discovery may be added under this label.

## Evidence record template (fill only after execution)

```text
TEST ID:
TRACK: A
PHASE: RECONNAISSANCE
ENVIRONMENT: LIVE PRODUCTION
TIMESTAMP:
TARGET:
OBJECTIVE:
TOOL:
COMMAND / METHOD:
REQUEST COUNT:
EXPECTED RESULT:
OBSERVED RESULT:
SECURITY CONTROL:
CLASSIFICATION:
FINDING:
SEVERITY:
IMPACT:
EVIDENCE FILES:
ANALYSIS:
COUNTERMEASURE:
SCOPE NOTES:
```

Use only these classifications: **CONFIRMED VULNERABILITY**, **SECURITY CONTROL SUCCESS**, **INFORMATIONAL OBSERVATION**, **PROVIDER/HOSTING LIMITATION**, **OUT-OF-SCOPE OBSERVATION**, or **INCONCLUSIVE**. Most ordinary Recon observations will be informational. A severity is assigned only when a confirmed issue warrants one and must be justified by exploitability, privileges, interaction and confidentiality/integrity/availability impact.

Store actual evidence only under `evidence/pentest/track-a/reconnaissance/`. Name a text file and, only when useful, a matching screenshot with the test ID, such as `A-REC-001_dns.txt` and `A-REC-001_dns.png`. Never create placeholder result files. Keep text evidence where possible; crop or redact screenshots. Exclude passwords, cookies, session identifiers, authorization/CSRF values, `.env` values, database credentials, private storage names, source identifiers/hashes and honeytoken secret material.

## Stop conditions

Stop immediately if another InfinityFree customer or provider infrastructure becomes the test subject; unexpected real private information appears; production becomes unstable or repeated 5xx responses occur; provider abuse controls activate; scope is uncertain; the test begins to require automation/fuzzing; or enough evidence has already been collected. Do not continue a redirected request to an off-origin destination. Record only the minimal sanitized observation and consult the guide.

## Academic report mapping

At least three distinct Recon methods should support the report:

1. **Domain/DNS observation** — A-REC-001. Implementation: one ordinary lookup. Result: fill after execution. Analysis: distinguish application name from provider address. Countermeasure/insight: discuss only an actual relevant exposure or successful boundary.
2. **TLS/certificate observation** — A-REC-002. Implementation: normal browser certificate inspection. Result: fill after execution. Analysis: hostname coverage and validity. Countermeasure/insight: recommend action only if a real certificate issue exists.
3. **HTTP and security-header observation** — A-REC-003 and A-REC-004. Implementation: one root response, then offline header review. Result: fill after execution. Analysis: security-policy structure and hosting differences. Countermeasure/insight: classify controls and gaps proportionately.
4. **Public source/asset and route mapping** — A-REC-006, A-REC-007 and A-REC-009. Implementation: inspect naturally delivered content and build an attributed route map. Result: fill after execution. Analysis: identify actual public inputs and any disclosure. Countermeasure/insight: do not claim undiscovered routes or imagined secrets.

For every report method, present **Implementation → Result → Analysis → Countermeasure → Insight**, citing its A-REC evidence. A-REC-005, A-REC-008 and A-REC-010 provide supporting interpretation when useful. No result has been fabricated in this planning document.

## Current handoff

The first future test is **A-REC-001 — Domain / DNS observation**. It has **not** been executed. The guide must provide that single instruction at the separately authorized execution turn, then wait for the operator's output before selecting any next test. Do not proceed to A-REC-002 now.
