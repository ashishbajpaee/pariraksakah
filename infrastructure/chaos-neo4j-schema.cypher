// Deliverable 3B: Neo4j Graph Schema for Chaos Engineering Platform
// Run via neo4j-admin or Cypher shell

// ═══ Constraints & Indexes ═══
CREATE CONSTRAINT chaos_experiment_id IF NOT EXISTS FOR (e:ChaosExperiment) REQUIRE e.experiment_id IS UNIQUE;
CREATE CONSTRAINT service_node_name IF NOT EXISTS FOR (s:ServiceNode) REQUIRE s.name IS UNIQUE;
CREATE CONSTRAINT scenario_id IF NOT EXISTS FOR (sc:ChaosScenario) REQUIRE sc.scenario_id IS UNIQUE;
CREATE CONSTRAINT mitre_ttp_id IF NOT EXISTS FOR (t:MitreTTP) REQUIRE t.ttp_id IS UNIQUE;

CREATE INDEX chaos_exp_status IF NOT EXISTS FOR (e:ChaosExperiment) ON (e.status);
CREATE INDEX gap_severity IF NOT EXISTS FOR (g:SecurityGap) ON (g.severity);

// ═══ Service Nodes (all Docker Compose services) ═══
MERGE (s:ServiceNode {name: 'api-gateway', port: 8080, language: 'Go', type: 'gateway'});
MERGE (s:ServiceNode {name: 'kafka', port: 9092, language: 'Java', type: 'messaging'});
MERGE (s:ServiceNode {name: 'timescaledb', port: 5432, language: 'C', type: 'database'});
MERGE (s:ServiceNode {name: 'neo4j', port: 7687, language: 'Java', type: 'database'});
MERGE (s:ServiceNode {name: 'redis', port: 6379, language: 'C', type: 'cache'});
MERGE (s:ServiceNode {name: 'threat-detection', port: 8001, language: 'Python', type: 'security'});
MERGE (s:ServiceNode {name: 'access-control', port: 8002, language: 'Go', type: 'security'});
MERGE (s:ServiceNode {name: 'anti-phishing', port: 8003, language: 'Python', type: 'security'});
MERGE (s:ServiceNode {name: 'incident-response', port: 8004, language: 'Go', type: 'security'});
MERGE (s:ServiceNode {name: 'bio-auth', port: 8005, language: 'Python', type: 'security'});
MERGE (s:ServiceNode {name: 'swarm-agent', port: 8006, language: 'Python', type: 'security'});
MERGE (s:ServiceNode {name: 'cognitive-firewall', port: 8007, language: 'Go', type: 'security'});
MERGE (s:ServiceNode {name: 'self-healing', port: 8008, language: 'Rust', type: 'security'});
MERGE (s:ServiceNode {name: 'mlflow', port: 5000, language: 'Python', type: 'ml'});
MERGE (s:ServiceNode {name: 'flink-jobmanager', port: 8082, language: 'Java', type: 'processing'});
MERGE (s:ServiceNode {name: 'prometheus', port: 9090, language: 'Go', type: 'observability'});
MERGE (s:ServiceNode {name: 'grafana', port: 3001, language: 'Go', type: 'observability'});
MERGE (s:ServiceNode {name: 'react-frontend', port: 3000, language: 'TypeScript', type: 'frontend'});
MERGE (s:ServiceNode {name: 'chaos-experiment-engine', port: 8020, language: 'Python', type: 'chaos'});
MERGE (s:ServiceNode {name: 'chaos-injection-agent', port: 8021, language: 'Rust', type: 'chaos'});
MERGE (s:ServiceNode {name: 'chaos-scheduler', port: 8022, language: 'Python', type: 'chaos'});
MERGE (s:ServiceNode {name: 'chaos-ai-intelligence', port: 8023, language: 'Python', type: 'chaos'});
MERGE (s:ServiceNode {name: 'chaos-guardrails', port: 8024, language: 'Go', type: 'chaos'});

// ═══ Service Dependency Relationships ═══
MATCH (gw:ServiceNode {name:'api-gateway'}), (td:ServiceNode {name:'threat-detection'}) MERGE (gw)-[:DEPENDS_ON]->(td);
MATCH (gw:ServiceNode {name:'api-gateway'}), (ac:ServiceNode {name:'access-control'}) MERGE (gw)-[:DEPENDS_ON]->(ac);
MATCH (gw:ServiceNode {name:'api-gateway'}), (ir:ServiceNode {name:'incident-response'}) MERGE (gw)-[:DEPENDS_ON]->(ir);
MATCH (gw:ServiceNode {name:'api-gateway'}), (ap:ServiceNode {name:'anti-phishing'}) MERGE (gw)-[:DEPENDS_ON]->(ap);
MATCH (fe:ServiceNode {name:'react-frontend'}), (gw:ServiceNode {name:'api-gateway'}) MERGE (fe)-[:DEPENDS_ON]->(gw);
MATCH (td:ServiceNode {name:'threat-detection'}), (k:ServiceNode {name:'kafka'}) MERGE (td)-[:DEPENDS_ON]->(k);
MATCH (td:ServiceNode {name:'threat-detection'}), (ts:ServiceNode {name:'timescaledb'}) MERGE (td)-[:DEPENDS_ON]->(ts);
MATCH (ir:ServiceNode {name:'incident-response'}), (k:ServiceNode {name:'kafka'}) MERGE (ir)-[:DEPENDS_ON]->(k);
MATCH (sh:ServiceNode {name:'self-healing'}), (k:ServiceNode {name:'kafka'}) MERGE (sh)-[:DEPENDS_ON]->(k);
MATCH (sh:ServiceNode {name:'self-healing'}), (ts:ServiceNode {name:'timescaledb'}) MERGE (sh)-[:DEPENDS_ON]->(ts);
MATCH (ce:ServiceNode {name:'chaos-experiment-engine'}), (k:ServiceNode {name:'kafka'}) MERGE (ce)-[:DEPENDS_ON]->(k);
MATCH (ce:ServiceNode {name:'chaos-experiment-engine'}), (ts:ServiceNode {name:'timescaledb'}) MERGE (ce)-[:DEPENDS_ON]->(ts);
MATCH (ci:ServiceNode {name:'chaos-injection-agent'}), (k:ServiceNode {name:'kafka'}) MERGE (ci)-[:DEPENDS_ON]->(k);
MATCH (ci:ServiceNode {name:'chaos-injection-agent'}), (ce:ServiceNode {name:'chaos-experiment-engine'}) MERGE (ci)-[:DEPENDS_ON]->(ce);
MATCH (cg:ServiceNode {name:'chaos-guardrails'}), (p:ServiceNode {name:'prometheus'}) MERGE (cg)-[:DEPENDS_ON]->(p);
MATCH (cg:ServiceNode {name:'chaos-guardrails'}), (r:ServiceNode {name:'redis'}) MERGE (cg)-[:DEPENDS_ON]->(r);
