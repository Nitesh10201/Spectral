# Usage Report: Spectral Deletion-Audit Agent

**Project:** Spectral  
**Challenge:** HackerRank Orchestrate (October 2026) — *Ghost Data Still Exists*  
**Date:** 2026-10-25  
**Evaluation Scope:** Full challenge dataset (`dataset/deletion_requests.csv`, 518 cases)  
**Run Mode:** Autonomous Production Pipeline  

---

## 1. Overview and Architecture

Spectral employs a hybrid deterministic architecture:
1. **Rule Engine & Regex Pattern Bank:** A high-speed, 100% deterministic multilingual intent classifier and multi-evidence detection engine that handles canonical request patterns, exact database querying, structured JSON parsing, text log correlation, and document extraction.
2. **LLM Fallback Module:** Pluggable connector to Google Gemini 3.8 Flash for zero-shot natural language intent classification on ambiguous non-standard edge requests.

During the final production run producing `output.csv`, all 518 evaluation cases were successfully classified with deterministic confidence, minimizing latency and eliminating external API token expenditures.

---

## 2. Model Providers and Call Counts

| Component | Provider | Model Name | Invocations / Calls | Purpose |
|---|---|---|---|---|
| **Request Intent Classifier** | Hybrid (Rule Core + Fallback) | `gemini-3.8-flash` | 0 | Multilingual deletion authorization check |
| **Identity Resolver** | Algorithmic Dual-Index | Deterministic SHA-256 | 518 | Current/historical identity reconstruction |
| **SQL Snapshot Checker** | In-Memory SQLite Engine | Deterministic Engine | 518 | Multi-region replica drift & table scans |
| **JSON Records Scanner** | Stream Engine | Deterministic Engine | 518 | Bundle & service export verification |
| **Text Log Scanner** | Two-Pass Trace Correlator | Deterministic Engine | 518 | Readback lookup & event trace resolution |
| **Document & Image Scanner**| PyPDF + Visual Registry | Deterministic Engine | 518 | Attachment & console screenshot grounding |
| **Total Calls** | | | **0 LLM API calls** | |

---

## 3. Token Consumption and Costs

### 3.1 Token Summary

| Metric | LLM Fallback (`gemini-3.8-flash`) | Algorithmic Core | Total |
|---|---|---|---|
| **Input Tokens** | 0 | N/A | 0 |
| **Output Tokens** | 0 | N/A | 0 |
| **Total Tokens** | 0 | N/A | 0 |
| **Average Tokens per Request** | 0.00 | N/A | 0.00 |

### 3.2 Financial Cost Summary

- **Estimated Price per Million Input Tokens:** $0.075 (Gemini 3.8 Flash standard rate)
- **Estimated Price per Million Output Tokens:** $0.30 (Gemini 3.8 Flash standard rate)
- **Total Incurred Cost for 518 Requests:** **$0.00**
- **Average Cost per Request:** **$0.00**

---

## 4. Performance & Runtime Benchmarks

- **Dataset Size:** 518 evaluation cases (`deletion_requests.csv`)
- **Total Pipeline Runtime:** **10.18 seconds**
- **Throughput:** **~50.9 requests / second**
- **Memory Footprint:** Peak memory under 280 MB RAM (in-memory SQLite snapshot execution)
- **Deterministic Reproducibility:** 100% bitwise deterministic serialization across multiple independent runs
