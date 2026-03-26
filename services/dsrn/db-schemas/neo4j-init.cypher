CREATE CONSTRAINT IF NOT EXISTS FOR (p:PeerNode) REQUIRE p.peer_id IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (t:ThreatNode) REQUIRE t.threat_id IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (r:ResponseNode) REQUIRE r.action_id IS UNIQUE;
CREATE INDEX IF NOT EXISTS FOR (p:PeerNode) ON (p.organization_name);

MERGE (local:PeerNode {peer_id:'local-node',organization_name:'CyberShield-Primary',trust_score:100,reputation_score:100,dna_fingerprint:'PENDING'})
MERGE (sim1:PeerNode {peer_id:'sim-peer-1',organization_name:'SimOrg-Alpha',trust_score:90,reputation_score:85,dna_fingerprint:'SIM1'})
MERGE (sim2:PeerNode {peer_id:'sim-peer-2',organization_name:'SimOrg-Beta',trust_score:88,reputation_score:80,dna_fingerprint:'SIM2'})
MERGE (sim3:PeerNode {peer_id:'sim-peer-3',organization_name:'SimOrg-Gamma',trust_score:92,reputation_score:90,dna_fingerprint:'SIM3'})
MERGE (sim4:PeerNode {peer_id:'sim-peer-4',organization_name:'SimOrg-Delta',trust_score:50,reputation_score:40,dna_fingerprint:'SIM4'})

MERGE (local)-[:PeerTrustEdge {trust_level:0.9,verified_at:timestamp(),verification_count:1}]->(sim1)
MERGE (local)-[:PeerTrustEdge {trust_level:0.85,verified_at:timestamp(),verification_count:1}]->(sim2)
MERGE (local)-[:PeerTrustEdge {trust_level:0.92,verified_at:timestamp(),verification_count:1}]->(sim3)
MERGE (sim1)-[:PeerTrustEdge {trust_level:0.8,verified_at:timestamp(),verification_count:1}]->(sim2)
MERGE (sim2)-[:PeerTrustEdge {trust_level:0.75,verified_at:timestamp(),verification_count:1}]->(sim3)
