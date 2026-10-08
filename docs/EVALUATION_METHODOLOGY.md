# Evaluation Methodology

## 1. Objectives and evidence sources

The framework measures what CHIMERA recorded, when it recorded it, how operational evidence changed a deterministic assessment, which synthetic deception was displayed, and whether an authorized lab retest changed after remediation. Inputs are `security_events`, `security_sessions`, `security_score_contributors`, `honeytoken_events`, `vulnerability_modules`, and `vulnerability_state_changes`.

## 2. Operational versus LAB evidence

Operational events may correlate to an operational security session. LAB events have category `LAB`, no security-session link, and zero contribution. Reports label them controlled LAB evidence; they do not inflate operational session, timing, score, or adaptive-profile metrics.

## 3. Threat-score interpretation

Phase 8 preserves Phase 5 exactly: ACCESS_DENIED 3, LOGIN_FAILURE 5, DOCUMENT_UPLOAD_REJECTED 5, ROLE_ACCESS_DENIED 10, SECURITY_RELEVANT_APPLICATION_ERROR 10, OWNERSHIP_ACCESS_DENIED 12, CSRF_REJECTED 12, DOCUMENT_INTEGRITY_FAILURE 20, DECOY_ACCESSED 20, and HONEYTOKEN_TRIGGERED 35. Other events contribute zero. LOW is 0–19, MEDIUM 20–44, HIGH 45–74, and CRITICAL 75–100.

The bounded score is reconstructed from persisted contributors. A disagreement is an integrity warning, never an automatic repair.

## 4. Detection Latency

Start is the first persisted operational event in a session. End is its first positive contributor. End minus start is reported in seconds. A contributing first event yields zero. Missing facts yield N/A. This is CHIMERA’s application-level definition, not a universal standard.

## 5. Time to Deception

Start is the first positive operational contributor. End is the first genuine `DECOY_ACCESSED` in that session. Profile selection, transition, and adaptive rendering are not endpoints. Missing interaction yields N/A.

## 6. Time to Honeytoken

Start is the first positive operational contributor. End is the first `HONEYTOKEN_TRIGGERED` in that session. Later duplicates do not replace the first timestamp. Missing interaction yields N/A.

## 7. Adaptive-profile evaluation

The framework counts selection, transition, render, and observed interaction under LOW, MEDIUM, HIGH, or CRITICAL metadata. It may report that an interaction was observed while a profile was active; it does not claim the profile caused that interaction.

## 8. Vulnerable-versus-remediated comparison

An authorized experiment repeats the same controlled method before and after Security Admin changes module state. Analytics reads `LAB_VULNERABILITY_INTERACTION`, `LAB_REMEDIATED_TEST`, and state history; it never performs the test. Missing outcome facts are `INSUFFICIENT EVIDENCE`.

## 9. Evidence export methodology

An exact Security Admin requests one allowlisted JSON or CSV type. Results are bounded to 1,000 rows, use stable display identifiers, and minimize fields. CSV values whose first non-whitespace character is `=`, `+`, `-`, or `@` receive a leading single quote.

## 10. Limitations and interpretation rules

- Report recorded, observed, measured, or correlated—not guaranteed or perfect.
- Treat LAB demonstrations separately from operational observations.
- Threat labels describe deterministic behavior assessment, not identity or intent.
- Report the measurable-session denominator with timing aggregates.
- Preserve inconsistent history and surface an integrity warning.
- Do not infer causal superiority from observed profile correlation.

Database/application clocks bound timestamp accuracy. Source identifiers identify an observed source, not a person. N/A is not zero. Results describe only the selected evidence population.

## 11. What CHIMERA can and cannot demonstrate

CHIMERA can demonstrate normalized capture, bounded session correlation, explainable score progression, deterministic adaptive presentation, deception interaction, controlled vulnerable/remediated comparison, and exportable evidence.

It cannot prove identity or intent, universal prevention, visibility outside the application, causal superiority of a profile, production-scale performance, or absence of every vulnerability. CHIMERA uses deterministic policy, not artificial intelligence or machine learning.

Phase 9 changes production safety and readiness only. Evidence generation, taxonomy, scoring, adaptive policy, lab methodology, and evaluation formulas remain unchanged and comparable.
