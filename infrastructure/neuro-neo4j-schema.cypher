// Deliverable 3: Neo4j Schema for Neuromorphic Security System

// 1. Constraints and Indexes
CREATE CONSTRAINT IF NOT EXISTS FOR (n:NeuronNode) REQUIRE n.neuron_id IS UNIQUE;
CREATE INDEX IF NOT EXISTS FOR (n:NeuronNode) ON (n.layer);

CREATE CONSTRAINT IF NOT EXISTS FOR (t:ThreatPatternNode) REQUIRE t.pattern_id IS UNIQUE;
CREATE INDEX IF NOT EXISTS FOR (t:ThreatPatternNode) ON (t.threat_type);

CREATE CONSTRAINT IF NOT EXISTS FOR (m:MemoryNode) REQUIRE m.memory_id IS UNIQUE;

CREATE CONSTRAINT IF NOT EXISTS FOR (e:EvolutionNode) REQUIRE e.checkpoint_id IS UNIQUE;

// Note: Properties for nodes and edges are dynamically attached as data is ingested.
// The following defines standard property structures used by the microservices:
// 
// Node: NeuronNode
// Properties: {neuron_id: String, layer: String, type: String, activation_threshold: Float, current_potential: Float}
//
// Edge: SynapseEdge (NeuronNode -> NeuronNode)
// Properties: {weight: Float, plasticity_rate: Float, last_updated: Integer, firing_count: Integer}
//
// Node: ThreatPatternNode
// Properties: {pattern_id: String, threat_type: String, mitre_ttp: String, confidence: Float}
//
// Node: MemoryNode
// Properties: {memory_id: String, encoding_strength: Float, decay_rate: Float}
//
// Edge: AssociativeEdge (MemoryNode -> MemoryNode or MemoryNode -> ThreatPatternNode)
// Properties: {association_strength: Float, co_activation_count: Integer}
//
// Node: EvolutionNode
// Properties: {checkpoint_id: String, generation: Integer, fitness_score: Float}

// Sample query to initialize a tiny foundation (optional, usually created dynamically)
// MERGE (n:NeuronNode {neuron_id: 'vortex-core-01', layer: 'prefrontal', type: 'LIF', activation_threshold: -55.0, current_potential: -70.0});
