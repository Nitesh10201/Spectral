# Spectral: AI-Powered Deletion-Audit Agent

**Challenge:** [HackerRank Orchestrate (October 2026) — Ghost Data Still Exists](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)  
**Agent Name:** Spectral  
**Platform:** Python 3.12+ / `uv`  

Spectral is an autonomous deletion-audit agent designed to detect ghost records, replica drift, exposed PII, active sync flows, and restore risks across complex distributed platforms. For every deletion request, it determines whether deletion was actually authorized, reconstructs the subject's current and historical identity trail bounded by `audit_at`, cross-references multi-modal evidence (SQL snapshots, JSON exports, service logs, PDF documents, and console screenshots), and synthesizes a strictly ordered remediation and verification plan.

---

## 1. Architecture Overview

Spectral is designed around a modular pipeline with pluggable evidence detectors:

```
                  ┌───────────────────────────────┐
                  │   dataset/deletion_requests   │
                  └──────────────┬────────────────┘
                                 │
                 ┌───────────────▼───────────────┐
                 │    HybridRequestClassifier    │── Non-Deletion ──► NOT_APPLICABLE (steps=[])
                 └───────────────┬───────────────┘
                                 │ Authorized Deletion
                 ┌───────────────▼───────────────┐
                 │       IdentityResolver        │◄── user_identities.csv + user_audit_log.csv
                 └───────────────┬───────────────┘    (Reconstructs emails, phones, hashes at audit_at)
                                 │
           ┌─────────────────────┼─────────────────────┐
           │                     │                     │
  ┌────────▼─────────┐  ┌────────▼─────────┐  ┌────────▼─────────┐  ┌───────────────────────┐
  │SqlSnapshotChecker│  │JsonRecordsScanner│  │  TextLogScanner  │  │DocumentAndImageScanner│
  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  └───────────┬───────────┘
           │ (SQLite replica     │ (Resource &         │ (2-Pass trace          │ (pypdf &
           │  drift & tables)    │  bundles)           │  correlation)          │  console registry)
           └─────────────────────┼─────────────────────┴────────────────────────┘
                                 │
                 ┌───────────────▼───────────────┐
                 │      PipelineOrchestrator     │◄── deletion_rules.csv
                 └───────────────┬───────────────┘
                                 │
                 ┌───────────────▼───────────────┐
                 │          StepBuilder          │
                 │      (sort_and_number_steps)  │
                 └───────────────┬───────────────┘
                                 │
                 ┌───────────────▼───────────────┐
                 │           output.csv          │
                 └───────────────────────────────┘
```

### Core Components

1. **`HybridRequestClassifier` (`code/pipeline/classifier/request_classifier.py`)**:
   - Detects negative deletion intent (access, rectification, marketing opt-out, export) across multiple languages.
   - Outputs `NOT_APPLICABLE` with `steps_json=[]` when deletion is unauthorized.
2. **`IdentityResolver` (`code/pipeline/identity/resolver.py`)**:
   - Dual-index over current snapshots and historical audit logs.
   - Temporal playback strictly bounded by each request's `audit_at` cutoff.
   - SHA-256 email hash generation and account-binding discovery.
3. **`SqlSnapshotChecker` (`code/detectors/sql/checker.py`)**:
   - In-memory SQLite execution of database snapshots.
   - Detects replication drift between primary tables and regional/failover replicas.
   - Scans search documents, customer profiles, and backup inventory tables.
4. **`JsonRecordsScanner` (`code/detectors/records/scanner.py`)**:
   - Analyzes service exports, customer data snapshot bundles, and export job tables.
   - Tracks lookups, anonymized audience profiles, connector states, and restore flags.
5. **`TextLogScanner` (`code/detectors/logs/scanner.py`)**:
   - Two-pass distributed trace correlator across application traces and lookup logs.
6. **`DocumentAndImageScanner` (`code/detectors/document/scanner.py`)**:
   - Extracts structured facts from PDF attachments using `pypdf`.
   - Inspects 11 admin console screenshots and shift handover records.
7. **`StepBuilder` & `Sorter` (`code/pipeline/steps/`)**:
   - Strict ordering: `PHASE_ORDER (FINDING -> REMEDIATION -> VERIFICATION)`, `OPERATION_ORDER`, `system_id`, `resource_id`.
   - 1-indexed consecutive step numbering and evidence grounding.

---

## 2. Setup & Installation

### Prerequisites
- Python 3.12 or higher
- `uv` (recommended) or `pip`

### Install Dependencies
Using `uv`:
```bash
uv sync
```
Or using standard `pip`:
```bash
pip install -r pyproject.toml
```

---

## 3. How to Run

### Run Full Pipeline on Evaluation Set (518 Cases)
To audit the full 518 cases from `dataset/deletion_requests.csv` and generate `output.csv` at the repository root:
```bash
uv run python code/main.py
```
Or with custom arguments:
```bash
uv run python code/main.py --dataset-dir dataset --requests dataset/deletion_requests.csv --output output.csv
```

### Run on Public Sample Set (32 Cases)
To test on the public sample dataset:
```bash
uv run python code/main.py --requests dataset/sample_deletion_requests.csv --output sample_pred.csv
```

---

## 4. Testing & Validation

### Run Unit Tests
Spectral includes 59 unit tests using synthetic fixtures:
```bash
uv run pytest
```

### Run Linter & Formatter
```bash
uv run ruff check
```

### Run Validation Harness
To validate any output CSV file against the official contest contract:
```bash
uv run python -c "from code.evaluation.harness.validator import validate_output_file; report = validate_output_file('output.csv', expected_count=518); print('Valid:', report.is_valid, 'Errors:', len(report.errors))"
```

---

## 5. Reports & Submission Links

- **Evaluation Report:** [`evaluation/evaluation_report.md`](evaluation/evaluation_report.md)
- **Token Usage Report:** [`evaluation/usage_report.md`](evaluation/usage_report.md)
- **Contest & Submission URL:** [https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)
