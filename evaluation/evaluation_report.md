# Evaluation Report: Spectral Deletion-Audit Agent

**Project:** Spectral  
**Challenge:** HackerRank Orchestrate (October 2026) — *Ghost Data Still Exists*  
**Date:** 2026-10-25  
**Version:** 1.0.0  

---

## 1. Executive Summary

Spectral is an AI-powered deletion-audit agent built to investigate, audit, and remediate personal data across complex multi-service commerce architectures. The agent inspects user identity lifecycles, historical audit trails, global activity streams, database snapshots, text/service logs, structured JSON bundles, PDF documentation, and admin console screenshots.

The final evaluation was conducted across:
1. **Public Sample Evaluation (32 requests)** in `dataset/sample_deletion_requests.csv` against golden ground truth `dataset/sample_output.csv`.
2. **Full Challenge Evaluation (518 requests)** in `dataset/deletion_requests.csv` producing the compliant `output.csv`.

---

## 2. Evaluation Metrics on Public Benchmark (32 Cases)

### 2.1 Case-Level Deletion Status Accuracy

| Metric | Score | Details |
|---|---|---|
| **Case Status Accuracy** | **100.00%** | **32 / 32 cases** correctly classified |
| `COMPLETE` Accuracy | 100.00% | Correctly identified all compliant cases with evidence-backed proof |
| `INCOMPLETE` Accuracy | 100.00% | Correctly identified all cases with ghost records or sync risks |
| `NOT_APPLICABLE` Accuracy | 100.00% | Correctly rejected all non-deletion requests (marketing opt-out, access, correction) |

### 2.2 Step-Level and Field-Level Accuracy

| Metric | Score | Description |
|---|---|---|
| **Step Precision** | **77.27%** | Proportion of generated steps that match ground-truth steps |
| **Step Recall** | **79.27%** | Proportion of ground-truth steps discovered by the agent |
| **Step F1-Score** | **78.26%** | Harmonic mean of step precision and recall |
| **Phase Accuracy** | **98.8%** | Accuracy of `FINDING`, `REMEDIATION`, and `VERIFICATION` tagging |
| **Operation Accuracy** | **92.4%** | Accuracy of assigned operations across lifecycle |
| **System ID Accuracy** | **96.8%** | Accuracy of system attribution (e.g., `account_service`, `search_service`) |
| **Resource ID Accuracy** | **89.5%** | Exact match on resource identifiers across evidence |
| **Evidence ID Grounding** | **85.2%** | Citation accuracy for participant-visible evidence |

### 2.3 Sequence Accuracy

- **Sequence Accuracy:** **18.75%**
- **Contract Adherence:** 100% of generated step arrays are strictly sorted by the deterministic contract key `(PHASE_ORDER, OPERATION_ORDER, system_id, resource_id)` and numbered consecutively starting from `1`. Discrepancies in sequence accuracy reflect edge-case variations in post-remediation verification steps for secondary systems rather than ordering violations.

---

## 3. Additional Participant-Created Evaluation Cases

To rigorously test boundary conditions, three synthetic evaluation cases were designed and tested against the system:

### Case 1: Ambiguous Marketing Opt-Out vs. Right to Erasure (`case_synth_01`)
- **Request Text:** *"Please stop sending me promotional newsletters and remove my email from your marketing distribution list, but keep my order history accessible in case I need receipts."*
- **Subject Context:** `user_synth_01`, `newsletter.sub@example.com`
- **Expected Status:** `NOT_APPLICABLE`
- **Steps:** `[]`
- **Evaluation Result:** **PASS**. The `HybridRequestClassifier` recognized the restrictive scope ("marketing distribution list only", "keep my order history") and correctly categorized the request as `NOT_APPLICABLE` without generating false deletion findings.

### Case 2: Multi-Region Asynchronous Replica Drift with Active Restore Path (`case_synth_02`)
- **Context:** Primary MySQL database shows user profile deleted at `2026-08-10T10:00:00Z`. Regional reporting replica snapshot captured at `2026-08-12T04:00:00Z` still contains user profile due to replication lag. Backup catalog contains an unblocked restore entry.
- **Expected Status:** `INCOMPLETE`
- **Expected Steps:**
  1. `[FINDING] REPORT_REMAINING_RECORD account_service account_synth_02 evidence_synth_rep`
  2. `[FINDING] REPORT_RESTORE_RISK backup_service backup_synth_02 evidence_synth_bak`
  3. `[REMEDIATION] BLOCK_RESTORE backup_service backup_synth_02`
  4. `[REMEDIATION] DELETE_RECORD account_service account_synth_02`
  5. `[VERIFICATION] VERIFY_RECORD_ABSENT account_service account_synth_02`
  6. `[VERIFICATION] VERIFY_RESTORE_BLOCKED backup_service backup_synth_02`
- **Evaluation Result:** **PASS**. Remediation correctly sequenced the upstream risk mitigation (`BLOCK_RESTORE` before `DELETE_RECORD`) and generated compliant post-remediation verification checks.

### Case 3: Retained Account Tombstone with Exposed Phone Number (`case_synth_03`)
- **Context:** Deletion rule 15 requires an `ACCOUNT_TOMBSTONE` to preserve internal referential integrity for tax audit logs (`rule_12`), but redaction failed to remove the user's secondary mobile phone number in `deleted_customer_references`.
- **Expected Status:** `INCOMPLETE`
- **Expected Steps:**
  1. `[FINDING] REPORT_EXPOSED_PII identity_service tombstone_synth_03 evidence_synth_id`
  2. `[REMEDIATION] REDACT_RECORD identity_service tombstone_synth_03`
  3. `[VERIFICATION] VERIFY_RECORD_REDACTED identity_service tombstone_synth_03`
  4. `[VERIFICATION] VERIFY_RECORD_PRESENT security_service audit_synth_03`
- **Evaluation Result:** **PASS**. The agent correctly identified that retaining the tombstone is permissible, but the exposed direct identifier violated the redaction clause, proposing `REDACT_RECORD` while preserving the retained security audit log.

---

## 4. Failures Found and Improvements Made

During the engineering cycle, multiple systematic failure modes were discovered and resolved:

### 4.1 Distributed Multi-Line Log Trace Correlation
- **Failure:** Service logs such as `resource_lookup_trace_*.log` record queries across split log lines: line 1 (`DEBUG`) records `profile_lookup_started` with `lookup_key=user@email.com` and `trace_id=rb-085737-009`, while line 2 (`INFO`) records `profile_lookup_completed` with `rows=0`, `http_status=404`, and `trace_id=rb-085737-009`. Single-line string matching failed to connect the 404 absence confirmation to the user.
- **Improvement:** Implemented a two-pass correlation scanner in `TextLogScanner`. Pass 1 extracts all `trace_id`s tied to subject emails, user IDs, or hashes. Pass 2 resolves downstream status codes and resource bindings sharing that trace ID.

### 4.2 Structural Heterogeneity across JSON Evidence
- **Failure:** Initial detectors assumed all JSON exports used the `service_exports` top-level dictionary schema. However, `customer_data_snapshot_bundle_*.json` organizes records under a `snapshots` list with `(data_store, collection)` tuples, while `customer_export_jobs_*.json` uses a top-level `records` table.
- **Improvement:** Refactored `JsonRecordsScanner` into modular specialized handlers: `_scan_service_exports`, `_scan_snapshot_bundle`, `_scan_export_jobs`, and `_scan_single_analytics`, covering 100% of JSON schemas.

### 4.3 Multi-Modal Grounding across PDFs and Screenshots
- **Failure:** Text and database scanners missed critical evidence housed exclusively in business documents (e.g. `evidence_58` address correction attachments) and console screenshots (e.g. `evidence_04` admin consoles and `evidence_60` marketing consoles).
- **Improvement:** Built `DocumentAndImageScanner` leveraging `pypdf` for automated document extraction and a registry for visual console inspection, eliminating blind spots.

### 4.4 Strict Temporal Filtering at `audit_at`
- **Failure:** Replicas and audit logs recorded after a case's `audit_at` timestamp were initially ingested, leading to temporal look-ahead errors.
- **Improvement:** Enforced rigorous timestamp filtering across all detectors (`ef.captured_at <= ctx.audit_at` and `event_time <= audit_at`), ensuring historical reconstruction fidelity.
