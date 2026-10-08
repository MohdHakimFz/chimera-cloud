# PROJECT CHIMERA - Kali Linux guides

These guides are beginner-oriented operator manuals, not permission to run every test in sequence. The controlling authorization and safety rules are [PENTEST_SCOPE_AND_ROE.md](../PENTEST_SCOPE_AND_ROE.md), with the dual-track method in [PENTEST_METHODOLOGY.md](../PENTEST_METHODOLOGY.md). The current reconnaissance test design is [TRACK_A_RECON_PLAN.md](../TRACK_A_RECON_PLAN.md); the frozen build is recorded in [PRE_PENTEST_TARGET_FREEZE.md](../PRE_PENTEST_TARGET_FREEZE.md). If a guide conflicts with the current rules of engagement, stop and follow the rules of engagement.

## Start here

- [Track A Reconnaissance Kali Linux Guide](TRACK_A_RECON_KALI_GUIDE.md) documents A-REC-001 through A-REC-010. **Only one test may be executed at a time.** The operator stops, sends sanitized evidence for analysis, and waits for approval before continuing.
- [Track A Scanning Kali Linux Guide](TRACK_A_SCANNING_KALI_GUIDE.md) documents the bounded manual A-SCAN-001 through A-SCAN-007 plan. Its controlling design is [TRACK_A_SCANNING_PLAN.md](../TRACK_A_SCANNING_PLAN.md). Recon completion does not automatically authorize any Scanning test.
- Track A is bounded, low-volume application-level work against the single CHIMERA production origin. InfinityFree infrastructure, other customers, provider hosts and IP ranges are out of scope. No broad automated scanning or exploitation is authorized by this guide.
- Track B is a separately approved, student-controlled isolated CHIMERA clone. Track B instructions must never be pointed at InfinityFree. Production LAB remains disabled.

Save initial evidence in Kali at `~/chimera-pentest-evidence/`. Do not assume a VMware shared folder exists. After review, transfer sanitized evidence to the Windows project directory `E:\My Project\Chimera\evidence\pentest\track-a\reconnaissance\`. Do not create invented result files.

Future guides may include `TRACK_A_GAINING_ACCESS_KALI_GUIDE.md`, `TRACK_B_RECON_KALI_GUIDE.md`, `TRACK_B_SCANNING_KALI_GUIDE.md`, and `TRACK_B_GAINING_ACCESS_KALI_GUIDE.md`. They have not been created here. Creating the Scanning guide does not execute or authorize any A-SCAN test or later phase.
