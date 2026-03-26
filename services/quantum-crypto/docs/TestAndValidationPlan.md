# Quantum-Ready Encryption - Test & Validation Plan

## 1. Cryptographic Correctness Tests
**Objective**: Guarantee that all data encrypted/signed with the new PQC and Hybrid modes correctly decrypts/verifies, ensuring no data loss or corruption during transit or storage.
- **T1: Hybrid Encryption & Decryption (Go Test)**:
  - Generate a random symmetric payload (using `Crypto Agility API`).
  - Call `/api/crypto/encrypt` using `Level: HYBRID`.
  - Expect: Correct symmetric decryption of the wrapper. Ensure metadata returns "hybrid_mode: active" and "algo: AES-256-GCM (Quantum Safe)".
- **T2: Hybrid Signatures (Go Test)**:
  - Generate a test payload and sign it using `Level: HYBRID`.
  - Parse the first two bytes to get the ECDSA length. Output the remaining bytes for ML-DSA. 
  - Expect: Both classical and PQC signatures must correctly verify.
- **T3: PQC Native Operations**:
  - Request `Level: PQC`. Validate that ONLY AES-256 and ML-DSA representations are produced. Attempt verification with classical keys, which MUST fail.

## 2. CBOM Scanner Tests
**Objective**: Ensure the codebase/infrastructure scanner correctly classifies known vulnerable cryptography primitives.
- **T4: Hardcoded Discovery**:
  - Produce a dummy python script containing `from cryptography.hazmat.primitives.asymmetric import rsa`.
  - Execute `cbom_scanner.py`.
  - Expect: Discovery of an asset categorized as `asymmetric`, algorithm `RSA`, and status `vulnerable` (RED).
- **T5: Protocol Vulnerability Detection**:
  - Launch a dummy TLS endpoint configured exclusively to `TLS_RSA_WITH_AES_128_CBC_SHA`.
  - Let scanner hit TLS port. 
  - Expect: Asset classified as `vulnerable` and flagged for ML-KEM replacement.

## 3. Data Re-Encryption Pipeline (Zero-Downtime Test)
**Objective**: Validate real-time AES-128 rotation to ML-KEM wrapped AES-256.
- **T6: Mock DB Rotation**:
  - Insert 5 mock rows encrypted under an AES-128 KEK.
  - Run the asynchronous rotation pipeline (`pipeline.py`).
  - Expect: All 5 rows seamlessly decrypt to the original plaintext but using the new PQC-safe KEK without throwing decryption anomalies. Ensure old KEK shredding log occurs.

## 4. PKI Certificate Chain Tests
**Objective**: Ensure hybrid certificate generation issues valid X.509 constructs that clients handle.
- **T7: Hybrid Cert Validation**:
  - Execute `pki_migration.py`.
  - Ensure the output certs contain an ML-DSA Object Identifier (OID) in the public key block along with SECP256R1 object logic.

## 5. Performance Benchmarks
**Objective**: Verify the hybrid layer does not introduce unacceptable latencies.
- **T8: High-Throughput Request Rate**:
  - Burst 10,000 requests per second against the Crypto Agility `/api/crypto/encrypt` API in HYBRID mode.
  - Target: <50ms P99 latency. Measure CPU impact due to dual signature evaluations.
  - Monitor memory load to track the burden of PQC public keys + signatures (since ML-DSA is large).

## 6. Regression Suite
- **T9: Graceful Degradation Test**:
  - Simulate a client handshake that only supports Classical Suites. Confirm the system defaults back safely to `LevelClassical` rather than breaking. (Supported during Phase 1-3 only).
