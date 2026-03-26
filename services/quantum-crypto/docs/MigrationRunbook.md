# Quantum-Ready Encryption Migration Runbook

## Phase 1: Inventory & Risk Assessment (Week 1–2)
**Owner**: Security Architecture Team
1. **Deploy CBOM Scanner**: Execute `cbom_scanner.py` across all environments.
   - Run: `docker compose up quantum-cbom-scanner`
   - Hit `/scan` API endpoint to traverse all repositories, TLS endpoints, and infrastructure.
2. **Review CBOM**: Review the generated `quantum:cbom:latest` in Redis. 
   - Identify all `RED` (vulnerable) assets.
   - Example priority: RSA-2048 JWT keys vs TLS ECDH keys.
3. **Draft Target Cryptography Map**: Assign replacements (e.g., ECDSA → ML-DSA (Dilithium)).

## Phase 2: Algorithm Upgrade - Symmetric & Hashes (Week 3–6)
**Owner**: Application Development Teams
1. **Hashing**: Replace MD5/SHA-1 across codebase using Crypto Agility API replacing raw library calls.
   - Upgrade SHA-256 to SHA-3-256 (where viable, since Grover halves effective strength).
2. **Symmetric Encryption**: 
   - Execute Data Re-Encryption Pipeline (`re-encryption/pipeline.py`)
   - Re-encrypt all AES-128 databases and object stores to AES-256.
   - Shred old AES-128 KEKs securely via KMS.

## Phase 3: Hybrid Mode Deployment (Week 7–12)
**Owner**: Platform / Infrastructure Team
1. **Enable TLS Hybrid Suites**: Update API Gateways (Envoy, Nginx, Go handlers) to prefer `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` + Kyber hybrid variations, using Open Quantum Safe (liboqs).
2. **PKI Hybrid Rotation**: 
   - Run automated rotation scripts (`pki/pki_migration.py`).
   - Issue x.509 certs wrapping both an ML-DSA and ECDSA public key.
   - Distribute via vault and cert-manager to container workloads.
3. **Crypto Agility Rollout**: Deprecate direct usage of `crypto/rsa` and `crypto/ecdsa`. Replace with API routing to the Crypto Agility Layer `HybridEngine`.

## Phase 4: Full PQC Migration (Month 4–6)
**Owner**: Compliance & Security Engineering
1. **Deprecate Classical Fallback**: After verifying all internal applications successfully negotiate Hybrid PQC securely, disable the Classical Engine entirely.
2. **Enforce ML-KEM/ML-DSA**: Only allow `LevelPQC` and `LevelHybrid` on Crypto Agility incoming requests.
3. **Data At Rest Key Rotation**: Key wrap all existing database AES-256 keys exclusively with ML-KEM, dropping any legacy RSA wrappers.
4. **Hardware Updates**: Flash HSMs to support pure PQC primitives (e.g. FIPS 204).

## Phase 5: Validation & Certification (Month 7)
**Owner**: Audit & GRC Teams
1. **Cryptographic Audit run**: Run CBOM Scanner one final time. Target: `quantum_readiness_score` = 100%.
2. **Red-Teaming**: Execute Quantum-Simulated Capture the flag. Verify standard algorithms can no longer read network traffic.
3. **Generate Compliance Package**: Export logs and metrics demonstrating that CNSA 2.0 and FIPS 140-3 transition rules have been adhered to.
