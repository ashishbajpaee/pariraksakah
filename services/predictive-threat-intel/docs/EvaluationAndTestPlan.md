# Model Evaluation Plan — AI Predictive Threat Intelligence

## Key Metrics

| Metric | Definition | Target |
|--------|-----------|--------|
| **Precision** | True Positives / (TP + FP) | ≥ 90% |
| **Recall (Sensitivity)** | True Positives / (TP + FN) | ≥ 88% |
| **False Positive Rate** | FP / (FP + TN) | ≤ 8% |
| **F1 Score** | Harmonic mean of P & R | ≥ 89% |
| **AUC-ROC** | Model discrimination | ≥ 0.95 |
| **Detection Latency** | Time from event to prediction | ≤ 200ms P99 |
| **Zero-Day Detection Rate** | Identified novel threats | ≥ 70% |

## Retraining Triggers
1. **Accuracy Degradation**: Precision or Recall drops below the target threshold based on rolling 7-day feedback labels.
2. **Model Drift**: Isolation Forest contamination estimator shifts significantly (Kolmogorov-Smirnov test p < 0.05 on feature distributions).
3. **Feedback Accumulation**: ≥ 200 new analyst-labeled samples (`true_positive`/`false_positive`) arrive since last training.
4. **Scheduled**: Every 6 hours via `RETRAIN_INTERVAL_HOURS` environment variable (default: 6h).
5. **Manual Trigger**: `GET /model/retrain` endpoint.

## Benchmarks
- **APT Simulation Test**: Inject 500 synthetic APT signals (MITRE stages T1190 → T1041). Expect Recall ≥ 88%.
- **Benign Flood Test**: 5,000 normal traffic signals. Expect FPR ≤ 8%.
- **Zero-Day Candidate Test**: Inject 50 high-anomaly, zero-IOC signals. Expect `is_zero_day_candidate: true` on ≥ 35 of them.
- **Throughput Test**: 2,000 req/s to `/predict`. Expect P99 ≤ 200ms.

# Test Plan — APT Scenario Validation

## Test 1: Credential Stuffing → Lateral Movement Chain
**Objective**: Validate the LSTM sequence predictor chains correctly from `credential_access` to `lateral_movement`.
**Signal**: `{ failed_auth_count: 250, distinct_ips: 12, unusual_geo_flag: 1, priv_escalation_attempts: 2 }`
**Expected**: severity=`High`, stage contains `lateral_movement`, attack_path includes `exfiltration`.

## Test 2: Data Exfiltration APT
**Objective**: Maximum-severity detection on full exfil signal.
**Signal**: `{ bytes_out_mb: 800, api_call_rate_per_min: 950, lateral_hop_count: 5, ioc_match_count: 8, cve_score_max: 9.8 }`
**Expected**: `threat_probability ≥ 90`, `severity = Critical`, `countermeasures` contains "Block outbound".

## Test 3: Zero-Day Candidate Flag
**Objective**: Detect novel behavior with no IOC matches.
**Signal**: High anomaly_score features but 0 IOC matches.
**Expected**: `is_zero_day_candidate: true`, model routes to Active Learning queue.

## Test 4: Benign Baseline Verification  
**Objective**: Normal user activity must NOT be flagged.
**Signal**: `{ login_hour: 9, failed_auth_count: 0, bytes_out_mb: 0.2, api_call_rate_per_min: 15 }`
**Expected**: `threat_probability ≤ 20`, `severity = Low`.

## Test 5: Feed Deduplication  
**Objective**: Duplicate IOCs from NVD and OTX for same CVE must produce exactly 1 IOC.
**Method**: Submit CVE-2024-21762 from two sources. Check Redis `threat:feed:count` only increments by 1.

## Test 6: UEBA Escalation Threshold
**Objective**: Entity crossing a risk score of 70 must publish to Redis `ueba:escalations` channel.
**Signal**: Inject event `{ priv_escalation_attempts: 4, lateral_hop_count: 5, unusual_geo_flag: 1 }`.
**Expected**: `risk_level = critical`, Redis publish fires, DB row has `escalated = true`.
