-- DSRN TimescaleDB Schemas
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS peer_registry (
    id TEXT PRIMARY KEY, peer_id TEXT NOT NULL UNIQUE, organization_name TEXT NOT NULL,
    public_key TEXT NOT NULL, dna_fingerprint TEXT NOT NULL, endpoint_url TEXT NOT NULL,
    trust_score DOUBLE PRECISION DEFAULT 100.0, reputation_score DOUBLE PRECISION DEFAULT 100.0,
    joined_at TIMESTAMPTZ DEFAULT NOW(), last_seen_at TIMESTAMPTZ DEFAULT NOW(), status TEXT DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS threat_intelligence_shared (
    id TEXT PRIMARY KEY, threat_id TEXT NOT NULL, source_peer_id TEXT NOT NULL,
    threat_type TEXT NOT NULL, severity TEXT NOT NULL, indicators JSONB,
    mitre_ttp TEXT, confidence_score DOUBLE PRECISION, validation_votes INTEGER DEFAULT 0,
    consensus_reached BOOLEAN DEFAULT FALSE, received_at TIMESTAMPTZ DEFAULT NOW(), validated_at TIMESTAMPTZ
);
SELECT create_hypertable('threat_intelligence_shared','received_at',if_not_exists=>TRUE);

CREATE TABLE IF NOT EXISTS response_actions (
    id TEXT PRIMARY KEY, action_id TEXT NOT NULL, proposed_by_peer_id TEXT NOT NULL,
    action_type TEXT NOT NULL, target TEXT, votes_for INTEGER DEFAULT 0,
    votes_against INTEGER DEFAULT 0, votes_abstain INTEGER DEFAULT 0,
    consensus_reached BOOLEAN DEFAULT FALSE, executed_at TIMESTAMPTZ, outcome TEXT
);

CREATE TABLE IF NOT EXISTS consensus_rounds (
    id TEXT PRIMARY KEY, round_id TEXT NOT NULL, proposal_hash TEXT NOT NULL,
    phase TEXT NOT NULL, participants JSONB, result TEXT,
    started_at TIMESTAMPTZ DEFAULT NOW(), completed_at TIMESTAMPTZ
);
SELECT create_hypertable('consensus_rounds','started_at',if_not_exists=>TRUE);

CREATE TABLE IF NOT EXISTS peer_reputation_history (
    id TEXT PRIMARY KEY, peer_id TEXT NOT NULL, reputation_score DOUBLE PRECISION NOT NULL,
    contributing_events JSONB, recorded_at TIMESTAMPTZ DEFAULT NOW()
);
SELECT create_hypertable('peer_reputation_history','recorded_at',if_not_exists=>TRUE);

CREATE TABLE IF NOT EXISTS distributed_ledger_blocks (
    id TEXT PRIMARY KEY, block_number INTEGER NOT NULL, block_hash TEXT NOT NULL,
    previous_hash TEXT NOT NULL, merkle_root TEXT NOT NULL, transactions JSONB,
    validator_signatures JSONB, created_at TIMESTAMPTZ DEFAULT NOW()
);
SELECT create_hypertable('distributed_ledger_blocks','created_at',if_not_exists=>TRUE);

CREATE TABLE IF NOT EXISTS dsrn_audit_trail (
    id TEXT PRIMARY KEY, action TEXT NOT NULL, peer_id TEXT NOT NULL,
    local_component TEXT, timestamp TIMESTAMPTZ DEFAULT NOW(), outcome TEXT NOT NULL, signature TEXT NOT NULL
);
SELECT create_hypertable('dsrn_audit_trail','timestamp',if_not_exists=>TRUE);

CREATE OR REPLACE FUNCTION dsrn_audit_immutable() RETURNS TRIGGER AS $$
BEGIN RAISE EXCEPTION 'dsrn_audit_trail is immutable'; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_dsrn_audit_immutable ON dsrn_audit_trail;
CREATE TRIGGER trg_dsrn_audit_immutable BEFORE UPDATE OR DELETE ON dsrn_audit_trail
FOR EACH ROW EXECUTE PROCEDURE dsrn_audit_immutable();
