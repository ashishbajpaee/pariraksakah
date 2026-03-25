-- Deliverable 3A: TimescaleDB Schema for Chaos Engineering Platform
-- Run against the existing 'cybershield' database

-- ═══ Chaos Experiments Hypertable ═══
CREATE TABLE IF NOT EXISTS chaos_experiments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scenario_id     UUID NOT NULL,
    name            TEXT NOT NULL,
    mitre_ttp       TEXT,
    attack_phase    TEXT,
    injection_type  TEXT,
    blast_radius    TEXT CHECK (blast_radius IN ('low','medium','high')),
    target_service  TEXT NOT NULL,
    status          TEXT CHECK (status IN ('pending','running','completed','aborted','failed')) DEFAULT 'pending',
    dry_run         BOOLEAN DEFAULT FALSE,
    start_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time        TIMESTAMPTZ,
    hypothesis      JSONB,
    rollback_steps  JSONB,
    metadata        JSONB
);
SELECT create_hypertable('chaos_experiments', 'start_time', if_not_exists => TRUE);

-- ═══ Chaos Results Hypertable ═══
CREATE TABLE IF NOT EXISTS chaos_results (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    experiment_id       UUID NOT NULL REFERENCES chaos_experiments(id),
    detection_time_ms   BIGINT NOT NULL,
    response_time_ms    BIGINT NOT NULL,
    mttr_ms             BIGINT NOT NULL,
    containment_score   DOUBLE PRECISION NOT NULL,
    resilience_score    DOUBLE PRECISION NOT NULL,
    false_negative_rate DOUBLE PRECISION NOT NULL,
    gaps_found          INTEGER DEFAULT 0,
    scorecard           JSONB,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('chaos_results', 'timestamp', if_not_exists => TRUE);

-- ═══ Chaos Gaps Table ═══
CREATE TABLE IF NOT EXISTS chaos_gaps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    experiment_id   UUID REFERENCES chaos_experiments(id),
    mitre_ttp       TEXT NOT NULL,
    service         TEXT NOT NULL,
    gap_type        TEXT NOT NULL,
    severity        TEXT CHECK (severity IN ('critical','high','medium','low')) NOT NULL,
    description     TEXT,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    remediated_at   TIMESTAMPTZ
);
SELECT create_hypertable('chaos_gaps', 'discovered_at', if_not_exists => TRUE);

-- ═══ Chaos Audit Trail (Immutable Append-Only) ═══
CREATE TABLE IF NOT EXISTS chaos_audit_trail (
    id              UUID DEFAULT gen_random_uuid(),
    action          TEXT NOT NULL,
    actor           TEXT NOT NULL,
    experiment_id   UUID,
    outcome         TEXT NOT NULL,
    details         JSONB,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('chaos_audit_trail', 'timestamp', if_not_exists => TRUE);

-- Enforce append-only: no UPDATE or DELETE
CREATE OR REPLACE RULE chaos_audit_no_update AS ON UPDATE TO chaos_audit_trail DO INSTEAD NOTHING;
CREATE OR REPLACE RULE chaos_audit_no_delete AS ON DELETE TO chaos_audit_trail DO INSTEAD NOTHING;

-- ═══ Behavioral Metrics (for Self-Healing baseline reference) ═══
CREATE TABLE IF NOT EXISTS behavioral_metrics (
    id              UUID DEFAULT gen_random_uuid(),
    component       TEXT NOT NULL,
    anomaly_score   DOUBLE PRECISION NOT NULL,
    cpu_usage       DOUBLE PRECISION,
    memory_usage    DOUBLE PRECISION,
    network_io      DOUBLE PRECISION,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('behavioral_metrics', 'timestamp', if_not_exists => TRUE);

-- ═══ Indexes for fast querying ═══
CREATE INDEX IF NOT EXISTS idx_chaos_exp_status ON chaos_experiments (status, start_time DESC);
CREATE INDEX IF NOT EXISTS idx_chaos_exp_target ON chaos_experiments (target_service, start_time DESC);
CREATE INDEX IF NOT EXISTS idx_chaos_results_exp ON chaos_results (experiment_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_chaos_gaps_sev ON chaos_gaps (severity, discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_chaos_audit_ts ON chaos_audit_trail (timestamp DESC);
