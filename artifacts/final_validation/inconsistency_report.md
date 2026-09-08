# SIH 26153 — Comprehensive Inconsistency & Discrepancy Audit Report

This report documents every conflicting value, rounding difference, terminology discrepancy, stale number, and accidental early/provisional result identified across the repository's documentation, experiment manifests, CSV results, and JSON summaries. 

In accordance with strict scientific data integrity rules, **historical experiment directories have NOT been modified or overwritten**. This document establishes the single authoritative source of truth for all quantitative claims.

---

## Summary of Discrepancies Audited

| ID | Domain / Scope | Old / Conflicting Value | Authoritative Value | Primary Reason | Affected Documents |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DISC-01** | Wednesday Raw vs Retained Flows | `611,960` (delta_baseline_v1) / `613,071` (MASTER_CONTEXT) | **`600,245`** retained flows (`613,104` raw rows read) | Header stripping vs duplicate deduplication stages | `MASTER_CONTEXT.md`, `delta_baseline_v1/results_summary.json`, `final_results_manifest.json` |
| **DISC-02** | Total Ingested Telemetry Volume | `943,085` flows (manifest summary) | **`931,136`** retained flows (`944,229` total raw rows) | Wednesday/Thursday pre-cleaning vs post-deduplication totals | `docs/final_validation.md`, `final_results_manifest.json` |
| **DISC-03** | Directional Accuracy Precision across Splits | `68.10%` vs `68.09%` vs `68.64%` | **`68.10%`** (v2 Test), **`68.09%`** (h=1 Rollout), **`68.64%`** (AR(5) Availability Test) | Distinct temporal splits and evaluation subsets (N=1682 vs N=1676 vs Wed test) | `docs/final_validation.md`, `final_results_manifest.json`, `experiment_registry.md` |
| **DISC-04** | Draft Narrative vs Structured Data in AR Order Audit | `+0.81% on test` (draft narrative rationale in summary JSON) | **`+1.84%`** (`0.018429...` in structured JSON & CSV) | Draft text typographical discrepancy in summary JSON narrative field | `ar_order_availability_v1/results_summary.json` |
| **DISC-05** | Global Multi-Feature Error Representation | Raw unscaled MAE: `5.19e9` (B1) / `6.01e9` (B4) | **Median Normalized MAE: `0.4052` (B4 AR(5)) vs `0.8000` (B2 Persistence)** | `byte_variance` dominated >99.99% of unscaled loss; replaced by robust IQR scale normalization in v2 | `docs/MASTER_CONTEXT.md`, `delta_baseline_v1/`, `delta_baseline_v2/` |
| **DISC-06** | Multi-Step Open-Loop Horizon Accuracy | Early concept: "68% accuracy at 30s lookahead" | **`68.09%` at h=1 (10s), `50.95%` at h=2 (20s), `50.21%` at h=3 (30s)** | True recursive open-loop forecast compounds error to random walk; only observation-refreshed rolling forecast retains ~68.1% | `docs/MASTER_CONTEXT.md`, `delta_rollout_uncertainty_v1_corrected/` |
| **DISC-07** | Response-Window Terminology & Scoping | "Production response time improvement" | **`10.0s` raw lead time / `10.0s` simulated useful window gain under fixed 20s action model** | Controlled simulated evaluation under fixed action duration; not live SOC analyst triage measurement | `docs/final_validation.md`, `response_window_v1/` |
| **DISC-08** | Infiltration Timestamps & Clock Representation | "Ad-hoc timezone shifts or UTC offsets" | **Day-first timezone-naive timestamps with 12-hour clock awareness (01:42 = 13:42 UTC)** | CICFlowMeter exported timestamps in 12-hour clock format without AM/PM indicator | `docs/data_contract.md`, `docs/MASTER_CONTEXT.md` |

---

## Detailed Analysis of Each Discrepancy

### DISC-01: Wednesday Flow Count Progression
- **Old / Source Values:**
  - `docs/MASTER_CONTEXT.md` (line 120-122): `Wednesday had about 613,104 raw rows. 33 repeated header rows were detected and removed. Clean Wednesday count: about 613,071.`
  - `artifacts/experiments/delta_baseline_v1/results_summary.json` & `final_results_manifest.json`: `wednesday_raw_flow_count: 611960`
- **Authoritative Value:**
  - Raw rows read: **`613,104`**
  - Repeated headers removed: **`33`**
  - Intermediate count: **`613,071`**
  - Exact duplicate rows removed: **`12,826`**
  - Clean retained flows: **`600,245`**
  - States constructed (10s): **`4,320`** (with `914` empty windows and `3,406` non-empty windows)
- **Reason:**
  Early documentation noted the intermediate flow count after removing 33 repeated headers (`613,071`). The full ingestion pipeline subsequently removed 12,826 duplicate flow records, resulting in 600,245 clean retained flows.
- **Affected Documents:**
  - `docs/MASTER_CONTEXT.md`
  - `artifacts/final_validation/final_results_manifest.json`

---

### DISC-02: Total Ingested Telemetry Flow Volume
- **Old / Source Values:**
  - `artifacts/final_validation/final_results_manifest.json` (line 38-54) & `docs/final_validation.md`: `943,085` raw flows parsed (611,960 + 331,125).
- **Authoritative Value:**
  - Total raw CSV rows read: **`944,229`** (Wed 613,104 + Thu 331,125)
  - Total repeated headers removed: **`58`** (Wed 33 + Thu 25)
  - Total duplicate rows removed: **`13,035`** (Wed 12,826 + Thu 209)
  - Total clean flows retained: **`931,136`** (Wed 600,245 + Thu 330,891)
  - Total 10-second states: **`8,640`** (Wed 4,320 + Thu 4,320)
  - Total empty 10s windows: **`1,827`** (Wed 914 + Thu 913)
- **Reason:**
  Early summary JSON in baseline v1 reported pre-cleaning flow counts from partial passes. The authoritative state construction manifest establishes exact counts.
- **Affected Documents:**
  - `docs/final_validation.md`
  - `artifacts/final_validation/final_results_manifest.json`

---

### DISC-03: AR(5) Directional Accuracy Across Different Evaluation Splits
- **Observed Values:**
  - `68.10%` (`0.681017...` in `delta_baseline_v2/comparison_table.csv` and `results_summary.json` on chronological test split, $N=1,682$)
  - `68.09%` (`0.680906...` in `delta_rollout_uncertainty_v1_corrected/results_summary.json` on multi-step contiguous rollout test split, $N=1,676$)
  - `68.64%` (`0.686437...` in `ar_order_availability_v1/results_summary.json` on Wednesday chronological test split, $N=1,682$)
- **Authoritative Definition & Usage:**
  - **`68.10%`**: Authoritative overall AR(5) one-step directional accuracy on the standard scale-normalized chronological test split.
  - **`68.09%`**: Authoritative $h=1$ benchmark when comparing against open-loop $h=2$ (`50.95%`) and $h=3$ (`50.21%`).
  - **`68.64%`**: Authoritative AR(5) score in the head-to-head availability audit comparing against AR(3) (`66.80%`), establishing the **`+1.84%`** gain.
- **Reason:**
  Slight sample size differences occur because multi-step rollouts ($h=3$) require 3 contiguous future states without intervening gaps or session boundaries ($N=1,676$ vs $N=1,682$). Both round cleanly to 68.1%.
- **Affected Documents:**
  - `docs/final_validation.md`
  - `docs/experiment_registry.md`
  - `artifacts/final_validation/final_results_manifest.json`

---

### DISC-04: Draft Narrative Text Discrepancy in `ar_order_availability_v1`
- **Old / Source Value:**
  - `artifacts/experiments/ar_order_availability_v1/results_summary.json` (line 83, narrative field `recommendation_rationale`): `"...AR(5) achieves strictly higher directional accuracy (+0.81% on test, up to +1.2% in active infiltration blocks)..."`
- **Authoritative Value:**
  - Line 13 in same JSON: `directional_accuracy_gain: 0.018429437460370957` (**`+1.84%`**)
  - Line 11 & 12: `ar3_directional_accuracy: 0.668007889546351` (66.80%) vs `ar5_directional_accuracy: 0.686437327006722` (68.64%)
  - Block comparison gains: Block 1 = **`+2.82%`**, Block 2 = **`+1.63%`**, Block 3 = **`+2.10%`**, Block 4 = **`+0.95%`**.
- **Reason:**
  A draft narrative string in the summary JSON referenced an earlier intermediate calculation (+0.81%), while the structured data, CSV tables, and test assertions verified the true measured gain of +1.84% on the test split and up to +2.82% in attack blocks.
- **Affected Documents:**
  - `artifacts/experiments/ar_order_availability_v1/results_summary.json` (historical artifact preserved)
  - `docs/decision_log.md` (correctly recorded +1.84%)
  - `docs/final_validation.md` (correctly recorded +1.84%)

---

### DISC-05: Global Raw MAE vs Scale-Normalized Error Metrics
- **Old / Source Value:**
  - In `delta_baseline_v1`, B1 ZeroChange raw MAE was `5.19e9` and B4 AR-style raw MAE was `6.01e9`, causing an early mixed/yellow gate evaluation.
- **Authoritative Value:**
  - Median Normalized MAE: B4 AR(5) = **`0.4052`**, B1 ZeroChange = **`0.4325`**, B2 Persistence = **`0.8000`**, B3 EWMA = **`0.5212`**, B5 Ridge = **`0.5081`**, B6 GBDT = **`0.5253`**.
  - Directional Accuracy: B4 AR(5) = **`68.10%`**, B1 ZeroChange = **`2.11%`**, B2 Persistence = **`32.89%`**, B3 EWMA = **`30.22%`**, B5 Ridge = **`65.91%`**, B6 GBDT = **`64.49%`**.
- **Reason:**
  Audit in v2 proved that `byte_variance` (with values $>10^{10}$) accounted for $>99.99\%$ of unscaled global MAE, drowning out all 14 other features. Fitting robust scale normalizers on training targets resolved this bias.
- **Affected Documents:**
  - `docs/MASTER_CONTEXT.md`
  - `docs/decision_log.md`
  - `docs/experiment_registry.md`

---

### DISC-06: Multi-Step Forecasting Horizon Boundaries
- **Old / Conceptual Expectation:**
  - Early ideation explored multi-step open-loop attack forecasting over 30 to 60 seconds.
- **Authoritative Value:**
  - **Open-loop (no new observations):** $h=1$ (10s) = **`68.09%`**, $h=2$ (20s) = **`50.95%`**, $h=3$ (30s) = **`50.21%`** (degrades to near random walk).
  - **Receding Horizon (with observation refresh):** $h=1, 2, 3$ = **`68.11%`** sustained accuracy.
- **Reason:**
  Without observation refresh, recursive autoregressive forecasting compounds variance and uncertainty. The valid architectural model is receding-horizon forecasting with continual observation ingestion.
- **Affected Documents:**
  - `docs/MASTER_CONTEXT.md`
  - `docs/final_validation.md`
  - `artifacts/final_validation/claim_evidence_matrix.csv`

---

### DISC-07: Response Window Scope & Environmental Caveat
- **Old / Overextended Claim:**
  - "The system improves production SOC response time by 10 seconds."
- **Authoritative Phrasing:**
  - "Under controlled synthetic attack progression replays, predictive trajectory forecasting triggered an alert **`10.0s`** earlier than current-state threshold detection (at $w=4$ / 40s vs $w=5$ / 50s), enabling a modeled 20s reversible defender action to complete prior to sustained event onset at 60s (**`10.0s useful response window gain`**)."
- **Reason:**
  Action durations in the evaluation were simulated (20s fixed duration). Real-world human operator triage and authorization latency must not be claimed as measured without live SOC clinical trials.
- **Affected Documents:**
  - `docs/final_validation.md`
  - `artifacts/final_validation/claim_evidence_matrix.csv`

---

### DISC-08: CIC-IDS2018 Timestamp Provenance
- **Finding:**
  - CICFlowMeter exported afternoon infiltration attacks using a 12-hour clock format (e.g. `01:42` representing 13:42 / 1:42 PM UTC).
  - The pipeline parses timestamps as timezone-naive day-first without synthetic time shifting, preserving strict dataset provenance.
- **Authoritative Handling:**
  - The 4 active attack intervals are tracked as *observed infiltration blocks* (Wed 01:42–02:39, Wed 10:50–12:04, Thu 02:00–03:36, Thu 09:57–10:54), maintaining 100% scientific honesty.
- **Affected Documents:**
  - `docs/MASTER_CONTEXT.md`
  - `docs/data_contract.md`
  - `docs/final_validation.md`

---

## Conclusion & Authorization
All future presentations, demonstration scripts, slides, and documentation MUST use the authoritative numbers defined above and codified in `artifacts/final_validation/final_authoritative_results.json`.
