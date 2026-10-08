# PROJECT CHIMERA  Track A Reconnaissance Kali Linux Guide

## Purpose

This is a practical, beginner-friendly manual for the ten planned Track A reconnaissance tests. It records *how* a future operator may perform a selected test; it is not a batch checklist to execute now. No results or classifications in this document are observed production facts. Use the current [Track A Recon Plan](../TRACK_A_RECON_PLAN.md), [Scope and Rules of Engagement](../PENTEST_SCOPE_AND_ROE.md), [Methodology](../PENTEST_METHODOLOGY.md), and [Target Freeze](../PRE_PENTEST_TARGET_FREEZE.md) as the authoritative control set.

## Scope

The sole live application target is `https://projectchimera.infinityfreeapp.com` (or its exact hostname for DNS and certificate observation). The CHIMERA application is in scope; InfinityFree infrastructure, provider IP addresses and networks, the control panel, database host, other virtual hosts and other customers are **out of scope**. Track B is a separate isolated clone, not a license to run Track B tools on production. The frozen production LAB remains `VULNERABILITY_LAB_ENABLED=false`.

## Important Rules

**ONLY ONE TEST MAY BE EXECUTED AT A TIME.** The guide selects the current ID, the operator performs only that ID, saves minimal sanitized evidence, stops, returns the result, and waits for analysis and explicit approval before the next ID. Do not paste multiple test commands into Terminal. Do not automate this guide.

Track A uses one deliberate, low-volume request where needed. Do not use production Nmap, Nikto, Nuclei, ffuf, Gobuster, Dirbuster, sqlmap, Hydra, Medusa, Metasploit, or Burp Active Scanner. No DoS/DDoS, brute force, fuzzing, directory or subdomain brute force, zone transfer, port scan, provider enumeration, high concurrency, destructive request, exploit, decoy interaction, honeytoken interaction, or LAB activation. Do not follow a redirect outside the exact CHIMERA origin.

Do not save or share passwords, cookies, session IDs, CSRF or authorization token values, `.env` contents, database credentials, private storage names, source identifiers/hashes, or honeytoken material. If an unexpected secret or real personal data appears, stop, do not retrieve more, and redact before sharing. Stop also for uncertain scope, repeated 5xx responses, instability, provider abuse controls, or sufficient evidence.

## How To Use This Guide

1. Open the Kali VM only when the current test is approved.
2. Open Terminal if that test needs one.
3. Locate the **one** approved A-REC section below.
4. Execute **only** its bounded command or manual procedure.
5. Save its text output or a concise observation note.
6. Take a screenshot only as specified, without secrets.
7. **STOP.** Do not open the next A-REC section as an execution task.
8. Send sanitized evidence to the guide for analysis and classification.
9. Continue only after the guide checks scope/safety and approves the next test.

## Beginner Kali basics

Open Terminal from the Kali panel icon or Applications menu. A typical prompt ends in `$` (sometimes `%`); the prompt is not part of the command. Type only the text inside a code block and press Enter once. `~` means your Kali home directory. `pwd` prints your current directory; `cd` changes directory; `mkdir` creates a directory. `tee` displays output while writing the same output to a file. `Ctrl+C` interrupts a running command; use it if a command hangs or behaves unexpectedly, then stop the test. A **command** is what you typed; **output** is what appears afterward. To copy output, select only the relevant text in Terminal and use its Copy menu or `Ctrl+Shift+C` (ordinary `Ctrl+C` interrupts instead). Avoid pressing the Up arrow and Enter after a network command: that may silently rerun it.

## Evidence setup

Before the first approved test, create a Kali-local directory. This command is local-only and makes no production request:

```bash
mkdir -p ~/chimera-pentest-evidence
```

`-p` allows the directory to exist already. Save actual A-REC evidence there. The Windows project destination is `E:\My Project\Chimera\evidence\pentest\track-a\reconnaissance\`; do **not** assume it is mounted in Kali or invent a Kali path for it. Transfer sanitized files afterward by an operator-approved method. A text filename and optional matching screenshot share the test ID. Do not create empty or fabricated result files.

## A-REC-001 - Domain / DNS Observation

### Objective
Observe an ordinary public IPv4 DNS answer for the exact CHIMERA hostname.

### Why We Are Doing This
Confirm the hostname being assessed and document public name resolution without probing the provider infrastructure behind it.

### Tool
Kali Terminal and `dig`. If `dig` is unavailable, stop and ask the guide whether to use `nslookup`; do not install tools or make duplicate lookups just for comparison.

### Before Running
Confirm A-REC-001 is the currently approved test. Open Terminal; check `command -v dig` (local-only). It should print a path. Create the Kali evidence directory using the command above. If the utility is absent, stop before DNS contact.

### Exact Command / Procedure
Run **once**:

```bash
dig +time=5 +tries=1 projectchimera.infinityfreeapp.com A | tee ~/chimera-pentest-evidence/A-REC-001_dns.txt
```

### Command Breakdown
`dig` asks DNS; `+time=5` limits the wait; `+tries=1` avoids repeat attempts; `projectchimera.infinityfreeapp.com` is the only name; `A` requests IPv4 records; `|` passes printed output to `tee`; `tee` displays and saves it in the Kali-local file. The DNS lookup contacts the configured resolver, not a discovered provider IP as a test target.

### What You Should See
A DNS response with a status and possibly QUESTION/ANSWER sections, or a clear lookup failure. No answer value is assumed.

### What To Look For
The exact queried hostname, `A` record type, response status, and any answer. A returned address is only an observation; it is not permission to probe that address.

### Evidence To Save
`A-REC-001_dns.txt` is saved by `tee`. Keep the result even if the lookup fails; do not rerun merely to obtain a prettier output.

### Screenshot
**OPTIONAL.** If useful, save `A-REC-001_dns.png` showing only the command and its response; crop unrelated terminal history.

### How To Interpret The Result
Successful public resolution is normally informational. A failure is recorded as observed and reviewed before any retry. Do not label either a vulnerability without further evidence.

### What NOT To Do
No other hostname, returned-IP probing, subdomain guessing, zone transfer, record sweep, or second lookup.

### STOP POINT
**STOP HERE. DO NOT EXECUTE THE NEXT A-REC TEST. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## A-REC-002 - TLS / Certificate Observation

### Objective
Observe the normal HTTPS certificate for the exact CHIMERA origin.

### Why We Are Doing This
Record hostname coverage, issuer and validity as externally visible connection facts.

### Tool
Kali web browser certificate/connection viewer. No cipher scanner or terminal command is needed.

### Before Running
Proceed only after A-REC-001 is analyzed and A-REC-002 is specifically approved. Close unrelated sensitive browser tabs. Use the exact CHIMERA origin, not a returned IP.

### Exact Command / Procedure
Open `https://projectchimera.infinityfreeapp.com` in the browser. Use the icon beside the address bar to open connection information and then certificate details. Record only the displayed subject/hostname coverage, issuer, validity dates and basic connection status. If your browser does not expose a field, write **not visible** rather than guessing or trying multiple tools without approval.

### Command Breakdown
No shell command. The single browser visit creates a normal HTTPS connection; the certificate viewer only displays connection details. Do not navigate to a provider page if redirected away from CHIMERA.

### What You Should See
A certificate-details panel or an explicit browser indication that details are unavailable. Values are unknown until observed.

### What To Look For
Whether the certificate covers the hostname and is within its validity interval. A provider-managed issuer alone is not a defect.

### Evidence To Save
Create a concise local note `A-REC-002_tls.txt` with observed fields, timestamp, method and any unavailable fields. Do not copy unrelated browser data.

### Screenshot
**RECOMMENDED** if the certificate panel clearly shows hostname and dates. Save `A-REC-002_tls.png`; crop account details and unrelated tabs.

### How To Interpret The Result
Matching, valid certificate information is a normal control observation. Any apparent mismatch or expiry needs guide review before classification; do not infer broad TLS weakness.

### What NOT To Do
No direct-IP connection, cipher enumeration, alternate ports, provider-host testing or repeated handshakes.

### STOP POINT
**STOP HERE. DO NOT EXECUTE THE NEXT A-REC TEST. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## A-REC-003 - Normal HTTP Response

### Objective
Observe one normal root response and its non-secret headers.

### Why We Are Doing This
Establish the public page's status, content type, redirect behavior and cache/server metadata without changing application state.

### Tool
Kali Terminal with `curl`. The guide may instead select browser DevTools if a provider challenge makes command-line output misleading.

### Before Running
Proceed only after A-REC-002 review and separate approval. Confirm the exact URL. The evidence directory must exist. Do not log in or attach cookies.

### Exact Command / Procedure
Run **once**. The filter removes any `Set-Cookie` header from saved and displayed evidence:

```bash
curl --max-time 15 --max-redirs 0 -sS -D - -o /dev/null https://projectchimera.infinityfreeapp.com/ | grep -vi '^set-cookie:' | tee ~/chimera-pentest-evidence/A-REC-003_http.txt
```

### Command Breakdown
`curl` makes one normal root GET; `--max-time 15` bounds waiting; `--max-redirs 0` does not follow redirects; `-sS` hides progress but shows errors; `-D -` prints response headers; `-o /dev/null` discards the body; the URL is the sole target. The first `|` sends headers to `grep -vi '^set-cookie:'`, which removes cookie-value lines regardless of case. The second `|` sends sanitized headers to `tee`, which displays and saves them. This is **one** network request; filtering and saving are local.

### What You Should See
An HTTP status line and headers, or a clear connection/error message. A hosting challenge or redirect may be observed; do not invent a CHIMERA response.

### What To Look For
Status, `Location` if present, content type, cache behavior and server-visible metadata. Do not follow an off-origin redirect.

### Evidence To Save
`A-REC-003_http.txt` is saved by `tee`. If an error appears only in Terminal and not the file, copy a sanitized error note into the evidence record without rerunning.

### Screenshot
**NOT REQUIRED** when text is clear; **OPTIONAL** for a browser challenge. Save `A-REC-003_http.png` only if useful, with cookie values excluded.

### How To Interpret The Result
A normal response is baseline behavior. A redirect or provider challenge must be identified as such. Status alone is not proof of a vulnerability.

### What NOT To Do
No automatic redirects, repeated retries, off-origin navigation, request-body submission or response-cookie recording.

### STOP POINT
**STOP HERE. DO NOT EXECUTE THE NEXT A-REC TEST. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## A-REC-004 - Security Header Observation

### Objective
Review security-relevant headers already captured in A-REC-003.

### Why We Are Doing This
Understand browser protection policies without making another production request.

### Tool
Kali text editor or file viewer for the saved A-REC-003 text. No new network command.

### Before Running
Wait for A-REC-003 analysis and specific approval. Use only its sanitized header file; if it captured a provider response, label it as provider output.

### Exact Command / Procedure
Open `A-REC-003_http.txt` locally. In a new note, record whether Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and Cache-Control are present, with non-secret policy structure. Mark a header **not observed** if absent. Do not issue another HTTP request.

### Command Breakdown
No shell command. This is offline interpretation of one already saved response.

### What You Should See
Header names and values where present; some may be absent or belong to a provider-generated response.

### What To Look For
The actual policy directives and which responder supplied them. Presence/absence alone is not a complete security judgment.

### Evidence To Save
Save the concise assessment as `A-REC-004_headers.txt` in the Kali evidence directory. Refer to `A-REC-003_http.txt` as its source.

### Screenshot
**OPTIONAL**, only if DevTools shows a policy more clearly. Save `A-REC-004_headers.png` without cookie values.

### How To Interpret The Result
Present controls can support a security-control success. An optional missing header is not automatically a vulnerability; assess context and browser effect first.

### What NOT To Do
No fresh request, cookie-value copying, header-manipulation test or CSP bypass attempt.

### STOP POINT
**STOP HERE. DO NOT EXECUTE THE NEXT A-REC TEST. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## A-REC-005 - Technology Fingerprinting

### Objective
Make evidence-backed technology observations from content already delivered normally.

### Why We Are Doing This
Describe the visible application stack without probing hosting software or guessing versions.

### Tool
Saved A-REC-003 headers and previously viewed public page/asset names; local text editor only.

### Before Running
Wait for A-REC-004 review and approval. Use only observations already collected. Separate fact from inference.

### Exact Command / Procedure
Create a three-column local note: **observed clue | possible interpretation | confidence**. Cite the earlier A-REC file or normal public page for each clue. Write **unknown** when evidence is insufficient. Do not run a fingerprint scanner or make a new request.

### Command Breakdown
No shell command. This test reuses earlier evidence offline.

### What You Should See
A short table of supported observations, perhaps with many unknowns. No version is assumed.

### What To Look For
Only publicly visible headers, HTML and asset conventions. A filename hint is weaker than an explicit version disclosure.

### Evidence To Save
Save `A-REC-005_technology.txt` in the Kali evidence directory, with source references.

### Screenshot
**NOT REQUIRED** unless one decisive public clue is clearer visually. If taken, save `A-REC-005_technology.png` without unrelated content.

### How To Interpret The Result
Record ordinary stack clues as informational. Do not label inferred technology or a guessed version as a confirmed issue.

### What NOT To Do
No active fingerprint scanner, server probing, version guessing or provider-IP testing.

### STOP POINT
**STOP HERE. DO NOT EXECUTE THE NEXT A-REC TEST. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## A-REC-006 - Public HTML / Source Inspection

### Objective
Inspect one normal public CHIMERA page's delivered HTML for links, forms, assets and accidental disclosure.

### Why We Are Doing This
Public source identifies input and navigation surfaces legitimately visible to an unauthenticated visitor.

### Tool
Kali browser, using **View Page Source** or DevTools Elements.

### Before Running
Wait for A-REC-005 review and approval. The guide selects the one public page, normally the CHIMERA homepage. Use a guest browser context; do not submit forms.

### Exact Command / Procedure
Open the selected page at the exact CHIMERA origin, then use the browser menu's **View Page Source**. Inspect delivered HTML for form actions and input *names*, links, asset references, comments, API references, debug strings, version labels and internal paths. Record a concise summary, not a raw full-page dump. Viewing source may cause a normal repeat page fetch; stop after this one selected page.

### Command Breakdown
No shell command. View Source displays HTML sent to the browser; it does not reveal server-side PHP source. Hidden input values may be live tokens and must not be copied.

### What You Should See
HTML tags and attributes for that public page, possibly including links and forms. Do not assume any particular route or disclosure.

### What To Look For
Public navigation and input names, plus any real accidental stack trace, secret, private path or internal URL. If sensitive material appears, stop and redact.

### Evidence To Save
Save a sanitized inventory as `A-REC-006_html.txt` in the Kali evidence directory. Record source page and timestamp.

### Screenshot
**NOT REQUIRED** by default. For a significant redacted observation, save `A-REC-006_html.png` showing only the relevant fragment and page identity.

### How To Interpret The Result
Normal public links/forms are informational. A suspected disclosure requires careful impact review; never reproduce a secret value in evidence.

### What NOT To Do
No form submission, protected-route request, full source dump containing hidden token values, or off-origin link following.

### STOP POINT
**STOP HERE. DO NOT EXECUTE THE NEXT A-REC TEST. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## A-REC-007 - Public JavaScript / Asset Observation

### Objective
Inspect at most one application JavaScript asset naturally referenced by the page reviewed in A-REC-006.

### Why We Are Doing This
Publicly delivered client code may identify normal route/API references or accidental disclosure.

### Tool
Kali browser DevTools Sources or Network panel.

### Before Running
Wait for A-REC-006 analysis and approval. The guide selects one actual asset reference from that page; do not guess a filename. If none is useful, record a justified skip.

### Exact Command / Procedure
In DevTools, open **only** the selected same-origin, directly referenced JavaScript asset. Read it without modifying or executing code manually. Note public route/API strings, validation rules, debug or source-map references and any suspected sensitive material. Do not open further assets without another decision.

### Command Breakdown
No shell command. DevTools inspection may use an asset already loaded by the page or make one normal request to that exact referenced URL. It is not a directory crawl.

### What You Should See
Client-side JavaScript or a normal load error. No particular route or secret is assumed.

### What To Look For
Evidence-backed references only; a route string is not proof that the route is public or vulnerable.

### Evidence To Save
Save sanitized observations with the exact referenced asset URL in `A-REC-007_assets.txt`. If skipped, record the reason in that note after approval.

### Screenshot
**OPTIONAL**, only for a significant redacted observation. Use `A-REC-007_assets.png` and show the asset identity plus relevant non-secret fragment.

### How To Interpret The Result
Normal public client code is informational. A suspected secret or internal value requires stopping and redacted review before classification.

### What NOT To Do
No guessed asset paths, directory enumeration, source-map crawling, new API requests or off-origin navigation.

### STOP POINT
**STOP HERE. DO NOT EXECUTE THE NEXT A-REC TEST. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## A-REC-008 - Standard Public Metadata

### Objective
Check one conventional application-level metadata file only if the guide decides it adds value.

### Why We Are Doing This
`robots.txt` may contain ordinary public crawling hints or a safe missing-file response; either helps describe the public surface.

### Tool
Kali browser address bar.

### Before Running
Wait for A-REC-007 review and specific approval. If earlier evidence makes this unnecessary, skip it with a reason. Do not use a wordlist.

### Exact Command / Procedure
Visit **once**: `https://projectchimera.infinityfreeapp.com/robots.txt`. Record the page's observed content/status or redirect. Do not follow any off-origin redirect and do not request paths named inside the file merely because they are listed.

### Command Breakdown
No shell command. This is one manual GET for a conventional file on the approved origin.

### What You Should See
Public text, a safe 404, a redirect or a provider response. No outcome is assumed.

### What To Look For
Only application-owned hints and whether the response is CHIMERA or provider-generated.

### Evidence To Save
Save `A-REC-008_metadata.txt` with URL, timestamp, result and any concise non-secret text. Do not save unrelated pages.

### Screenshot
**NOT REQUIRED** unless a significant non-secret observation is clearer visually; then save `A-REC-008_metadata.png`.

### How To Interpret The Result
Presence or absence of `robots.txt` is normally informational, not a vulnerability. Disallow lines are not authorization to access those paths.

### What NOT To Do
No other guessed metadata paths, recursive browsing, wordlists, or following listed paths.

### STOP POINT
**STOP HERE. DO NOT EXECUTE THE NEXT A-REC TEST. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## A-REC-009 - Public Route Mapping

### Objective
Build a conservative route map from naturally discovered CHIMERA links and references.

### Why We Are Doing This
Later planning needs a traceable list of apparent application surfaces without brute-force discovery.

### Tool
Local text editor and the saved A-REC-003, A-REC-006, A-REC-007 and A-REC-008 evidence.

### Before Running
Wait for A-REC-008 review and approval. Reuse existing records only; do not request mapped routes in this step.

### Exact Command / Procedure
Create a local table with **route/path | discovery source | apparent purpose | provisional category | tested?**. Categories are PUBLIC, AUTHENTICATION, REGISTRATION, PROTECTED, or UNKNOWN/NOT TESTED. Mark routes as untested unless already observed through approved normal behavior. Do not infer access from a visible link alone.

### Command Breakdown
No shell command and no new network request; this is offline mapping.

### What You Should See
A bounded map with a source citation for each entry. Unknowns are acceptable.

### What To Look For
Navigation links, form actions, normal redirect destinations and client asset references already captured.

### Evidence To Save
Save `A-REC-009_routes.txt` in the Kali evidence directory. Redact token-bearing query strings if any appear.

### Screenshot
**NOT REQUIRED**. An optional `A-REC-009_routes.png` may support one important visible link, with sensitive values excluded.

### How To Interpret The Result
A discovered path is only an attack-surface lead. It does not establish accessibility, a vulnerability or authorization behavior.

### What NOT To Do
No route crawler, forced browsing, authentication test, protected-route visit or invented route.

### STOP POINT
**STOP HERE. DO NOT EXECUTE THE NEXT A-REC TEST. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## A-REC-010 - Information Disclosure Review

### Objective
Review the accumulated A-REC evidence for actual accidental information disclosure.

### Why We Are Doing This
Consolidate observations without deliberately provoking production errors.

### Tool
Local text editor; previously sanitized A-REC-001 through A-REC-009 records only.

### Before Running
Wait for A-REC-009 review and approval. Have the earlier evidence available. Do not make new production requests.

### Exact Command / Procedure
Review existing records for stack traces, filesystem paths, SQL errors, configuration, debug output, credentials/tokens, internal hostnames, private storage details and source identifiers. For each possible disclosure, note the source evidence, what was actually exposed, confidence and possible impact **without copying a secret value**. Record none observed if appropriate.

### Command Breakdown
No shell command. This is offline analysis, not an error-generation test.

### What You Should See
A short evidence-linked list, which may have no disclosure candidates. Do not invent findings.

### What To Look For
Actual sensitive detail, not ordinary public technology clues. If a real secret or unrelated person's data is present, stop and ask for handling guidance.

### Evidence To Save
Save `A-REC-010_disclosure-review.txt` with sanitized source references and rationale.

### Screenshot
**NOT REQUIRED**; refer to an earlier redacted screenshot only if necessary. Do not make a fresh production screenshot for this offline review.

### How To Interpret The Result
Classify each supported outcome as CONFIRMED VULNERABILITY, SECURITY CONTROL SUCCESS, INFORMATIONAL OBSERVATION, PROVIDER/HOSTING LIMITATION, OUT-OF-SCOPE OBSERVATION, or INCONCLUSIVE only after guide review. Ordinary Recon findings are often informational; severity needs actual impact evidence.

### What NOT To Do
No deliberate malformed requests, reproduction of secrets, fresh probing or automatic move into Scanning.

### STOP POINT
**STOP HERE. DO NOT EXECUTE ANOTHER PHASE. SEND THE RESULT / SCREENSHOT FOR ANALYSIS FIRST.**

## Evidence review reminder

For each *executed* test, record ID, timestamp, exact target, method, request count, expected and observed result, evidence filename, classification, impact, and scope notes. Never fill observed results in advance. Do not continue after a possible disclosure, provider boundary, instability, uncertain authorization or sufficient proof. The next test always requires a separate guide decision.

At publication of this manual, **A-REC-001 is the first operator step**. The later sections are reference material only until each is individually authorized and the preceding evidence has been reviewed.
