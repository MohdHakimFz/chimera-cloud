# PROJECT CHIMERA — Track A Scanning Evidence-Review Guide for Kali

**Manual evidence review completed — 7/7 per operator report.** This remains a local-only evidence-hygiene and reproducibility guide. It does not authorize another production request, a repeat A-SCAN test, Gaining Access, Track B, or LAB activation. The operator reports reviewing and accepting the seven Kali records; Codex has **not independently accessed those files** from the Windows workspace. Read [the consolidated review](TRACK_A_SCANNING_CONSOLIDATED_REVIEW.md), [Scope and ROE](PENTEST_SCOPE_AND_ROE.md), and [the Scanning Plan](TRACK_A_SCANNING_PLAN.md) for the accepted narrow conclusions and unresolved academic-submission tasks.

## 1. Start safely

Open Kali Terminal. A prompt ending in `$` shows where to type; do not type the `$` itself. The commands in this guide are **local file checks**, not HTTP/DNS/scanning commands. They contain no production hostname. Do not run any browser, curl, scanner or pentest command to fill an evidence gap. If the directory is absent, stop and report that; do **not** create empty evidence files.

```bash
cd ~/chimera-pentest-evidence
pwd
```

`cd` changes to the existing Kali-local evidence folder; `pwd` prints the current path. Confirm it ends in `/chimera-pentest-evidence`. This is **not** the Windows project directory. Do not assume a VMware shared-folder mount.

## 2. Verify the seven expected text files

Run this local metadata-only command. It does **not** print file contents:

```bash
ls -l -- A-SCAN-001_auth-forms.txt A-SCAN-002_session-attributes.txt A-SCAN-003_user-forms-csrf.txt A-SCAN-004_role-aware-soc-surface.txt A-SCAN-005_owned-document-workflow.txt A-SCAN-006_passive-browser-request-inventory.txt A-SCAN-007_profile-validation.txt
```

`ls -l` lists existence, size and modified time; `--` ends option parsing. A `No such file or directory` line means the named file is missing *under that exact name*, not that the test never happened. Do not fabricate it. If names differ, list only A-SCAN files in this folder, without recursion:

```bash
find . -maxdepth 1 -type f -name 'A-SCAN-*' -printf '%f\n'
```

`find .` searches this directory; `-maxdepth 1` forbids a recursive search; `-type f` selects files; `-name` limits names to A-SCAN; `-printf` prints filenames only. Match any alternative filename to its test ID and note the mismatch. Do not rename evidence until its provenance is understood.

If the seven exact files exist, check that each is nonempty without displaying content:

```bash
wc -c -- A-SCAN-001_auth-forms.txt A-SCAN-002_session-attributes.txt A-SCAN-003_user-forms-csrf.txt A-SCAN-004_role-aware-soc-surface.txt A-SCAN-005_owned-document-workflow.txt A-SCAN-006_passive-browser-request-inventory.txt A-SCAN-007_profile-validation.txt
```

`wc -c` reports byte counts. A zero-byte file is incomplete. Size alone does not establish quality. If a file is missing, `wc` reports an error; do not substitute a guessed result. After redaction and only if useful for transfer integrity, compute hashes of the **sanitized** files:

```bash
sha256sum -- A-SCAN-001_auth-forms.txt A-SCAN-002_session-attributes.txt A-SCAN-003_user-forms-csrf.txt A-SCAN-004_role-aware-soc-surface.txt A-SCAN-005_owned-document-workflow.txt A-SCAN-006_passive-browser-request-inventory.txt A-SCAN-007_profile-validation.txt
```

`sha256sum` prints a digest and filename, not contents. It proves later copies match these files; it cannot prove the observation is true or that the files are secret-free. A missing-file error is a review item, not a reason to repeat production testing. The seven records' current status is **MANUALLY REVIEWED / ACCEPTED (OPERATOR)**. If an item later proves missing, inconsistent or secret-bearing, record that change explicitly. Do not equate operator review with `INDEPENDENTLY VERIFIED BY CODEX`.

## 3. Perform a safe completeness review

Open one file at a time in a local text editor using Kali's file manager. **Do not paste raw files into chat or an academic report.** Read locally and prepare a separate sanitized summary. For each ID, check timestamp/time zone, exact CHIMERA target/path, account role, tool/manual method, request count, expected versus observed behavior, status/message where applicable, screenshot reference, cleanup, classification and scope notes. Distinguish a test that was executed from a test whose evidence supports a conclusion.

| ID | Minimum observation to reconcile with its record |
|---|---|
| A-SCAN-001 | Guest login/register forms actually observed; action/method/field names and token **presence**, no values. |
| A-SCAN-002 | One USER login/logout; primary cookie Secure/HttpOnly true and SameSite=None; separate `__test` cookie ownership unknown; post-logout `/dashboard` 302 with no protected content. No cookie or credential values. |
| A-SCAN-003 | Three observed USER forms (`/profile`, `/documents`, `/logout`); delete form **not observed**; CSRF presence not overstated as enforcement. |
| A-SCAN-004 | USER and Security Admin contexts separated; seven SOC surfaces, LAB displayed DISABLED and three modules REMEDIATED; visible navigation not overstated as direct RBAC proof. |
| A-SCAN-005 | One synthetic TXT owner workflow; final visible 0 documents / 0 B. Operator's **Kali-local** original/download SHA-256 values match and `cmp -s` passed. App-displayed checksum was not preserved; do not claim it was checked. |
| A-SCAN-006 | 4 USER + 7 Security Admin page captures, 7 entries each, 77 total **entries, not unique endpoints**; no XHR/API observed only within capture windows. |
| A-SCAN-007 | One three-whitespace own-profile submission, displayed 2–100-character validation message, unchanged original name; do not infer broad sanitization. |

For screenshots, check locally whether each optional `A-SCAN-<ID>_*.png` supports the text and is readable. A screenshot is not required when a sufficiently detailed text record exists. Do not screenshot a live production page again merely to fill a gap. If the text and screenshot disagree, mark INCONSISTENT and record the precise conflict without repeating the test.

## 4. Identify missing or inconsistent observations

The operator reports all seven files were present and manually reviewed. If a future reviewer cannot find one, mark **MISSING**, search only the Kali-local evidence folder by ID as above, and ask for the original record. Several text records lack execution timestamps: do not manufacture times; consult genuine screenshot/file metadata only if attributable, otherwise say **timestamp unavailable**. Missing role, target, observation or cleanup detail is **PARTIAL**. Conflicting status, role, request count or fixture lifecycle is **INCONSISTENT**. Secret-bearing evidence is **REDACTION REQUIRED** before sharing. Keep any raw original local and access-controlled; do not overwrite it to conceal a discrepancy. Create a separate redacted copy for academic submission.

Do **not** make a new production request to resolve an evidence gap under this review task. A later repeat, if genuinely necessary, needs its own ROE decision and request budget. Do not infer an API call from local source code when A-SCAN-006 did not observe one. Do not infer server CSRF enforcement from a hidden input or authorization from navigation alone. Do not interpret a missing optional screenshot as a failed control.

## 5. Redaction requirements

Before copying, transferring or sending any excerpt, remove or crop: passwords/password hashes, `.env`/database credentials, Cookie/Set-Cookie values, session IDs, CSRF/authorization token values, `source_ip`, `source_hash`, `source_safe_identifier`, internal source identifiers, private `storage_name`/filesystem paths, honeytoken material, private documents, unrelated account records and unnecessary personal data. For A-SCAN-005 retain only a harmless fixture descriptor and, if necessary, its synthetic numeric ID. For A-SCAN-002 report cookie **attribute names and present/absent values** only, never the cookie value itself. A screenshot showing DevTools Storage or Headers must be cropped/redacted before academic use.

As a **filename-only warning check**, this local command can flag text files that may need closer manual redaction review. It prints matching **filenames only**, not matching lines or secret values. A match may be harmless discussion, and no match is **not** a secret-scan pass:

```bash
grep -lEi 'set-cookie:|cookie:|authorization:|source_ip|source_hash|source_safe_identifier|storage_name|password[[:space:]]*[:=]|_token.*value' -- A-SCAN-00[1-7]_*.txt
```

Do not use `grep -n` or paste a matching line into chat; it may reveal the very value being screened. Inspect flagged files locally in the editor and redact a separate review copy. Do not upload raw evidence to an unapproved service.

## 6. Classify findings conservatively

The completed operator review classified A-SCAN-001–005 and 007 primarily **SECURITY CONTROL SUCCESS**, secondarily **INFORMATIONAL OBSERVATION**; A-SCAN-006 primarily **INFORMATIONAL OBSERVATION**, secondarily **EXPECTED APPLICATION BEHAVIOR**. That last phrase is descriptive, **not** a seventh ROE classification. The review identified **zero confirmed vulnerabilities within these seven bounded tests**, not a vulnerability-free application. Retain the ROE labels for any later correction: **CONFIRMED VULNERABILITY**, **SECURITY CONTROL SUCCESS**, **INFORMATIONAL OBSERVATION**, **PROVIDER/HOSTING LIMITATION**, **OUT-OF-SCOPE OBSERVATION**, or **INCONCLUSIVE**. A route, form, cookie name, SameSite=None value, missing screenshot or source-code expectation is not by itself a vulnerability. A hidden CSRF field is not server enforcement; a role-aware menu is not direct RBAC proof.

For a supported control, state the observed action and the specific boundary that resisted it; do not claim broader protection. If evidence is ambiguous, use INCONCLUSIVE and say why. Countermeasures should address a **verified** weakness; otherwise record a limitation or future validation decision. Do not silently remediate during frozen-target evidence collection.

## 7. Final review and closure checklist

- [x] Operator reports all seven A-SCAN records manually read, reviewed and accepted with the classifications above. Codex has not independently opened them.
- [x] Operator reports A-SCAN-005 local original/download SHA-256 match and `cmp -s` PASS, with no additional production request; owner deletion left a visible 0-document / 0 B state.
- [x] A-SCAN-007's original name remained unchanged after the single invalid submission.
- [ ] Resolve missing execution timestamps where genuine attributable metadata exists; otherwise explicitly state that they are unavailable.
- [ ] Crop/redact any screenshots that still reveal sensitive values before academic submission; review text copies separately.
- [ ] If evidence is transferred to Windows, preserve the exact seven verified filenames and reconcile text/screenshots without claiming Codex verification before inspection.
- [ ] Academic Scanning analysis includes more than two distinct methods, actual reported implementation/results, narrow interpretation, countermeasure only where warranted, and the **logical** scope diagram—not invented provider topology.
- [ ] Final reviewer signs off on any remaining evidence-hygiene gap before declaring academic submission ready.
- [x] **Gaining Access remains NOT STARTED.** Next-phase testing requires a separate scope and authorization decision.

The sanitized per-test findings supplied by the operator are now recorded in the consolidated review. Do not send raw secrets, full cookie/header dumps or unredacted screenshots. The review status is **MANUAL EVIDENCE REVIEW COMPLETED — 7/7; DOCUMENTATION READY FOR FINAL REVIEW**, with Codex-independent inspection unavailable and the timestamp/screenshot submission tasks above still open. This guide ends at Scanning documentation review; it does not begin Gaining Access planning or execution.
