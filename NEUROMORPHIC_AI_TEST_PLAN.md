# Neuromorphic AI Security System — Test & Validation Plan

## 1. Unit Tests (Spiking Neural Network & Neuron Biology)
- **Spike Propagation:** Validate that an input current > -55mV threshold over 20ms indeed triggers a `SpikeEvent` out of the Brian2 array.
- **Membrane Potential Recovery:** Verify that after a spike, the membrane resets perfectly to -70mV and does not fire again within the 2ms refractory period.
- **Rate Coding Correctness:** Input severity of 10 must translate to high-frequency spikes; severity of 1 must translate to sparse bursts.

## 2. Learning Rule Validation Tests (Synaptic Plasticity)
- **STDP Validation:** Provide pairs of pre and post synaptic spikes within a 20ms delta_t. Confirm weight delta follows `delta_w = A_plus * exp(-delta_t / tau_plus)`.
- **Hebbian Co-activation:** Inject repeated simultaneous spikes into two inputs -> Verify their mutual connective weights are strengthened (LTP) over time.
- **Homeostatic Adjustment:** Flood network continuously to hit 30 Hz -> Verify homeostatic scalar reduces network firing rate back towards 10 Hz target.

## 3. Integration & Flow Tests
- **End-to-End Latency:** Inject realistic `P11` traffic packet into Go API Gateway -> ensure spike generated -> SNN -> Kafka -> Cortex Classification is completing in < 50ms overhead.
- **Database Consistency:** After STDP update, run SQL assertion targeting `synaptic_weights_history` to confirm valid hash signatures, weights, and `update_trigger`.

## 4. Threat Detection & Learning Validation (MITRE)
- **Initial Training:** Stream the `/datasets/mitre/enterprise-attack.json` via the Integration Consumer.
- **Epoch Verification:** Validate True Positive Rate (TPR) exceeds 80% after 20 epochs of supervised streaming (rewarding correct identifications via `POST /plasticity/reward`), reaching target baseline of TPR.

## 5. Memory System Tests (Hippocampus)
- **Memory Formation:** Assert new unseen 0-day simulated spikes generate a Sparse Distributed Memory representation via `hippocampus_core.py`.
- **Decay Forgetting Curve:** Fast-forward system time by 2 days; weak memories with strength < 0.2 must be correctly pruned from active dict and database. Strong confirmed threats (strength > 0.8) must remain.
- **Recall Trigger:** Send previously seen threat spike pattern. Cosine similarity must read > 0.85, generating immediate neuro.memory.recalled Kafka event.

## 6. Dream Consolidation Tests
- **NREM Triggering:** Spin down mock traffic volume below 20%. Wait 30m. Verify DreamCycle engine automatically starts.
- **Generalization:** Validate NREM Phase 2 combines 3 highly similar Lateral Movement threats into 1 generalized parent node in Neo4j (Graph traversal check).

## 7. Adaptive Immune System Tests (Go API Gateway/Falco)
- **Antibody Generation:** Threat detected by SNN -> Assert `neuro-adaptive-immune` caches the malicious `pattern` in Redis as an antibody.
- **Response Validation:** Inject new HTTP request matching antibody -> Assert Go API Gateway returns `403 Forbidden` instantly via Redis lookup before triggering the SNN engine.

## 8. Evolution & Architecture Tests
- **Stagnation Trigger:** Mock fitness function returning plateaued score 85% for 48h. Verify `POST /evolution/trigger` handles architecture mutation (layer neuron count variance).
- **Shadow Mode Accuracy:** Run Shadow architecture alongside Primary. If Shadow scores +4% TPR, assert automatic promotion and swap over.

## 9. Adversarial Tests
- **Evasion Attacks:** Feed mathematically crafted low-low-frequency multi-channel attack designed to slip beneath LIF integration thresholds. Validate if Cortex Anomaly region escalates the strange "quietness" below baseline activity level.
