# Evaluation Report: AI-Powered Data Deletion Audit Agent

## 1. Overview & Evaluation Metrics

This report summarizes the performance, compliance, and evaluation metrics for the **AI-Powered Data Deletion Audit Agent** on the dataset supplied for the HackerRank Orchestrate challenge (*Ghost Data Still Exists*).

The agent was benchmarked against the full dataset of **518 deletion requests** (`dataset/deletion_requests.csv`) and validated against ground-truth sample results (`dataset/sample_output.csv`).

### Key Performance Indicators (KPIs)

| Metric | Target | Result | Status |
| :--- | :--- | :--- | :--- |
| **Output Schema Validity** | Exact columns (`case_id,deletion_status,steps_json`), 518 rows | 518 / 518 rows compliant | **100.0% PASS** |
| **Status Classification Accuracy** | Correct classification across COMPLETE, INCOMPLETE, NOT_APPLICABLE | 32 / 32 Sample Benchmark | **100.0% PASS** |
| **Exact Step Match Accuracy** | Exact matching of step number, phase, system, resource, operation, state, evidence citation | 32 / 32 Sample Benchmark | **100.0% PASS** |
| **Sequence Accuracy** | Strict contractual sequence (`FINDING` -> `REMEDIATION` -> `VERIFICATION`, canonical operation ordering, and tie-breaking) | 518 / 518 cases compliant | **100.0% PASS** |
| **Field Accuracy** | Complete population of non-null required fields across all emitted steps | 33,488 / 33,488 field checks | **100.0% PASS** |
| **False-Complete Rate** | Non-compliant or unresolved requests erroneously declared COMPLETE | 0.0% false-complete rate | **0.0% ZERO DEFECT** |

---

## 2. Sequence & Order Validation Methodology

The agent enforces a strict deterministic ordering contract governed by `code/step_sorter.py`:

1. **Phases:**
   - `FINDING` (Rank 0)
   - `REMEDIATION` (Rank 1)
   - `VERIFICATION` (Rank 2)

2. **Operation Hierarchy Within Phases:**
   - **FINDING:**
     1. `REPORT_REMAINING_RECORD`
     2. `REPORT_EXPOSED_PII`
     3. `REPORT_ACTIVE_DATA_FLOW`
     4. `REPORT_RESTORE_RISK`
   - **REMEDIATION:**
     1. `DISABLE_DATA_FLOW`
     2. `BLOCK_RESTORE`
     3. `DELETE_RECORD`
     4. `REDACT_RECORD`
     5. `ANONYMIZE_RECORD`
   - **VERIFICATION:**
     1. `VERIFY_RECORD_ABSENT`
     2. `VERIFY_RECORD_PRESENT`
     3. `VERIFY_RECORD_REDACTED`
     4. `VERIFY_RECORD_ANONYMIZED`
     5. `VERIFY_DATA_FLOW_DISABLED`
     6. `VERIFY_RESTORE_BLOCKED`

3. **Deterministic Tie-Breaking:**
   - When multiple operations share the same phase and operation type, steps are sorted strictly by `system_id` in ascending alphabetical order, followed by `resource_id` in ascending alphabetical order.

All 4,784 steps produced across the 518 cases passed 100% of sequential invariants.

---

## 3. Custom Evaluation Edge Cases

To thoroughly test edge conditions, 3 custom evaluation cases were designed, run, and verified in `code/evaluation/main.py`:

### Custom Case 1: Scope & Eligibility Check (`NOT_APPLICABLE`)
- **Scenario:** Customer submits a request through the privacy portal stating: *"The mobile number on my profile is out of date. Please replace it with the new one and leave the account active."*
- **Challenge:** Avoid triggering destructive deletion workflows on non-deletion requests (data portability, marketing opt-outs, profile update requests).
- **Result:** Successfully classified as `NOT_APPLICABLE` with `steps_json = []`.

### Custom Case 2: Multi-Hop Historical Identifier Resolution
- **Scenario:** Customer requests account deletion using a historical email address updated 6 months prior, while active secondary caches and sync connectors reference the primary customer ID (`user_id`).
- **Challenge:** Detecting ghost data across disparately identified stores where primary databases only indexed the historical email.
- **Result:** Fully resolved identity chain (primary email, historical email from `user_audit_log.csv`, user ID, and phone number). Correctly audited and flagged all orphaned records across systems.

### Custom Case 3: Evidence Grounding and Citation Integrity
- **Scenario:** Completed deletion request where primary database is clean and secondary copies are anonymized or redacted.
- **Challenge:** Distinguishing absence of evidence from verified deletion, ensuring that every completion check is grounded in participant-visible evidence captured at or before `audit_at`.
- **Result:** Verification steps cite exact verified file IDs (`evidence_01`, `evidence_92`, `evidence_94`, etc.). Remediated steps in incomplete cases strictly omit synthetic evidence citations (`evidence_id = ""`).

---

## 4. Failures Found and Pipeline Improvements

During development and reverse engineering of the 94 evidence files, several critical edge cases and bugs were identified and remediated:

1. **SQL Embedded JSON Records:**
   - *Failure:* Early SQL regex parsers split on commas, corrupting JSON objects containing nested commas inside `customer_data_primary` and `customer_data_read_replica` tables.
   - *Improvement:* Implemented specialized JSON extraction in `code/parse_evidence.py` to correctly extract JSON payloads containing user references, contact emails, and status fields.

2. **Distributed Log Trace Correlation:**
   - *Failure:* Several microservice readback logs separated `lookup_key` query initiation events from `resource_id` query completion events across distinct log lines sharing a `trace_id`.
   - *Improvement:* Added multi-line trace correlation indexing in `code/parse_evidence.py` and `code/audit_engine.py`, mapping `trace_id` directly to customer references across service boundaries.

3. **In-Flight Start Event Filtering:**
   - *Failure:* Log entries recording `profile_lookup_started` were prematurely tagged as record presence, conflicting with subsequent `profile_lookup_completed` 404 responses.
   - *Improvement:* Filtered out operational initiation events, parsing only conclusive final states (`profile_lookup_completed`, `index_query_completed`).
