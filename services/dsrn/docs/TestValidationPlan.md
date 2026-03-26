# Test & Validation Plan: Decentralized Security Response Network

## 1. Unit Tests

### 1.1 Byzantine Consensus (Go)
- **test_quorum_calculation**: Verify `quorum(4)=3`, `quorum(7)=5`, `quorum(10)=7`
- **test_max_faulty**: Verify `maxFaulty(4)=1`, `maxFaulty(10)=3`
- **test_consensus_with_all_honest**: 4 honest peers → consensus in <5s
- **test_consensus_with_1_byzantine**: 3 honest + 1 Byzantine → correct result
- **test_view_change**: Primary timeout → new primary elected → consensus resumes

### 1.2 Gossip Protocol (Python)
- **test_bloom_dedup**: Same threat_id submitted twice → second rejected as duplicate
- **test_hop_count_limit**: Threat with hop_count=10 → not propagated further
- **test_anonymization**: IP `10.0.1.42` anonymized to `10.0.1.0/24`, hostname hashed
- **test_stale_threat_rejection**: Threat older than 24 hours → not propagated

### 1.3 Blockchain Ledger (Rust)
- **test_genesis_block**: Chain starts with valid genesis block
- **test_block_hash_chaining**: Each block.previous_hash == previous_block.block_hash
- **test_merkle_root**: Merkle of empty transactions differs from merkle of 1 tx
- **test_chain_integrity**: Modifying any block invalidates verification

### 1.4 Peer Trust Manager (Python)
- **test_reputation_weights**: 30% intel quality + 20% participation + 20% FP rate + 15% network + 15% identity = 100
- **test_byzantine_detection**: Peer with (0.3 quality, 0.2 participation, 0.45 FP) → flagged as Byzantine
- **test_blacklist_on_detection**: Flagged peer score set to 0, added to blacklist

## 2. Integration Tests

### 2.1 End-to-End Threat Intel Lifecycle
1. Local system detects threat indicator
2. Submitted to gossip protocol → anonymized
3. Gossip propagates to 3 random peers
4. Each peer submits to consensus for validation
5. Consensus reaches COMMITTED
6. Validated intel stored in TimescaleDB
7. Block created in ledger containing the transaction

### 2.2 End-to-End Response Coordination
1. Peer proposes "block_ip" response for malicious IP
2. Response coordinator assigns 51% threshold
3. 3/4 peers vote FOR → consensus reached
4. Response committed and broadcast
5. All peers execute local IP block

## 3. Byzantine Fault Injection Tests

### 3.1 Malicious Peer Submitting False Intel
- Inject peer that submits fake threat intel repeatedly
- Verify: trust score drops, eventually ejected via consensus

### 3.2 Inconsistent Voting
- Peer votes PREPARE but never sends COMMIT
- Verify: consensus still reaches correct result with 2f+1 honest peers

### 3.3 Sybil Attack Simulation
- Spin up 5 fake peer containers with different IDs but same source
- Verify: trust manager detects correlated behavior, flags as Sybil

### 3.4 Eclipse Attack Simulation
- Single peer floods routing table by connecting from many endpoints
- Verify: network monitor detects dominant routing, alerts raised

## 4. Network Partition Tests

### 4.1 Split Network
- Use `docker network disconnect` to split 4 peers into 2 groups of 2
- Verify: each partition continues operating independently
- Reconnect: verify chains merge correctly

### 4.2 Leader Isolation
- Disconnect primary consensus leader
- Verify: view change occurs within 10s, new leader elected

## 5. Performance Tests

### 5.1 Consensus Latency
- 10 peer nodes, 100 concurrent proposals
- Passing: P95 consensus < 30 seconds

### 5.2 Gossip Propagation
- Single threat intel shared from 1 peer
- Passing: reaches all 10 peers within 60 seconds (4 gossip rounds)

### 5.3 Ledger Throughput
- Submit 1000 transactions in 60 seconds
- Passing: all captured in blocks, chain valid

## 6. Privacy Tests

### 6.1 No Internal Data Leakage
- Share 100 threat intel items
- Parse all outbound messages
- Verify: zero internal IPs, zero internal hostnames, zero service names

### 6.2 Rate Limiting
- Attempt to share 1001 items in 24 hours
- Verify: 1001st item rejected with HTTP 429

## 7. End-to-End Scenario: Coordinated Multi-Org Attack Response
1. Org-Alpha detects ransomware indicators (C2 IP + file hash)
2. Shares via gossip → reaches Org-Beta, Gamma, Delta within 30s
3. Org-Beta correlates with local SIEM data, confirms match
4. Org-Beta proposes "quarantine" response → 67% threshold
5. 3/4 peers vote FOR → consensus committed
6. All orgs quarantine matching services within 60s
7. Results shared back to network as defensive intel
8. Full event chain recorded in immutable ledger
