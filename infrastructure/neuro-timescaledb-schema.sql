-- Deliverable 3: TimescaleDB Schema for Neuromorphic Security System

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- 1. neural_spike_log
CREATE TABLE IF NOT EXISTS neural_spike_log (
    id UUID DEFAULT gen_random_uuid(),
    neuron_id VARCHAR(100) NOT NULL,
    layer VARCHAR(50) NOT NULL,
    spike_time TIMESTAMPTZ NOT NULL,
    membrane_potential DOUBLE PRECISION,
    input_pattern_hash VARCHAR(256),
    threat_context JSONB,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('neural_spike_log', 'recorded_at', if_not_exists => TRUE);

-- 2. synaptic_weights_history
CREATE TABLE IF NOT EXISTS synaptic_weights_history (
    id UUID DEFAULT gen_random_uuid(),
    synapse_id VARCHAR(100) NOT NULL,
    pre_neuron VARCHAR(100) NOT NULL,
    post_neuron VARCHAR(100) NOT NULL,
    weight_before DOUBLE PRECISION NOT NULL,
    weight_after DOUBLE PRECISION NOT NULL,
    learning_rule VARCHAR(50) NOT NULL,
    update_trigger VARCHAR(100),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('synaptic_weights_history', 'updated_at', if_not_exists => TRUE);

-- 3. learned_threat_patterns
CREATE TABLE IF NOT EXISTS learned_threat_patterns (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    pattern_id VARCHAR(100) UNIQUE NOT NULL,
    pattern_hash VARCHAR(256) NOT NULL,
    threat_type VARCHAR(100),
    mitre_ttp VARCHAR(100),
    confidence_score DOUBLE PRECISION,
    times_recognized INTEGER DEFAULT 1,
    first_learned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    synaptic_encoding JSONB
);

-- 4. anomaly_detections
CREATE TABLE IF NOT EXISTS anomaly_detections (
    id UUID DEFAULT gen_random_uuid(),
    anomaly_id VARCHAR(100) NOT NULL,
    source_service VARCHAR(100) NOT NULL,
    anomaly_type VARCHAR(100) NOT NULL,
    spike_pattern JSONB,
    membrane_potential_trace JSONB,
    confidence_score DOUBLE PRECISION,
    false_positive BOOLEAN DEFAULT FALSE,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('anomaly_detections', 'detected_at', if_not_exists => TRUE);

-- 5. memory_traces
CREATE TABLE IF NOT EXISTS memory_traces (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    memory_id VARCHAR(100) UNIQUE NOT NULL,
    threat_id VARCHAR(100),
    encoding_strength DOUBLE PRECISION,
    recall_count INTEGER DEFAULT 0,
    last_recalled_at TIMESTAMPTZ,
    decay_rate DOUBLE PRECISION,
    associated_memories JSONB,
    formed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. dream_consolidation_log
CREATE TABLE IF NOT EXISTS dream_consolidation_log (
    id UUID DEFAULT gen_random_uuid(),
    cycle_id VARCHAR(100) NOT NULL,
    patterns_consolidated INTEGER DEFAULT 0,
    weights_updated INTEGER DEFAULT 0,
    memories_strengthened INTEGER DEFAULT 0,
    memories_pruned INTEGER DEFAULT 0,
    cycle_duration_ms BIGINT,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('dream_consolidation_log', 'completed_at', if_not_exists => TRUE);

-- 7. neuro_audit_trail (immutable append-only)
CREATE TABLE IF NOT EXISTS neuro_audit_trail (
    id UUID DEFAULT gen_random_uuid(),
    action VARCHAR(100) NOT NULL,
    neuron_layer VARCHAR(50),
    component VARCHAR(100) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    outcome VARCHAR(50),
    spike_signature VARCHAR(256)
);
SELECT create_hypertable('neuro_audit_trail', 'timestamp', if_not_exists => TRUE);

-- Create trigger to enforce immutability on neuro_audit_trail
CREATE OR REPLACE FUNCTION prevent_update_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Updates and Deletes are not allowed on this immutable table.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER make_neuro_audit_trail_immutable
BEFORE UPDATE OR DELETE ON neuro_audit_trail
FOR EACH ROW EXECUTE FUNCTION prevent_update_delete();
