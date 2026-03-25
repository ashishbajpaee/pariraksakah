import React, { useState, useEffect, useCallback } from 'react';

// ═══ Types ═══
interface Experiment {
  experiment_id: string;
  name: string;
  status: string;
  target_service: string;
  blast_radius: string;
  start_time: string;
  end_time?: string;
  dry_run: boolean;
}

interface ResilienceResult {
  experiment_id: string;
  resilience_score: number;
  containment_score: number;
  detection_time_ms: number;
  response_time_ms: number;
  mttr_ms: number;
  false_negative_rate: number;
  timestamp: string;
}

interface Gap {
  id: string;
  mitre_ttp: string;
  service: string;
  severity: string;
  gap_type: string;
  discovered_at: string;
  remediated_at?: string;
}

interface Prediction {
  service: string;
  failure_probability: number;
  confidence: number;
  last_resilience_score: number;
}

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const CHAOS_ENGINE_URL = `${API_BASE}/api/chaos`;

// ═══ Sub Components ═══
const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const colors: Record<string, string> = {
    running: '#22C55E', completed: '#3B82F6', aborted: '#EF4444',
    failed: '#EF4444', pending: '#F59E0B',
  };
  return (
    <span style={{
      background: colors[status] || '#6B7280',
      color: '#fff', padding: '2px 10px', borderRadius: 12, fontSize: 12, fontWeight: 600,
    }}>{status.toUpperCase()}</span>
  );
};

const MetricCard: React.FC<{ label: string; value: string | number; target: string; met: boolean }> = 
  ({ label, value, target, met }) => (
  <div style={{
    background: '#1E293B', borderRadius: 8, padding: 16, border: `1px solid ${met ? '#22C55E30' : '#EF444430'}`,
    flex: '1 1 140px',
  }}>
    <div style={{ color: '#94A3B8', fontSize: 11, marginBottom: 4 }}>{label}</div>
    <div style={{ color: met ? '#22C55E' : '#EF4444', fontSize: 22, fontWeight: 700 }}>{value}</div>
    <div style={{ color: '#64748B', fontSize: 10 }}>Target: {target}</div>
  </div>
);

// ═══ Main Component ═══
const ChaosEngineering: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [experiments, setExperiments] = useState<Record<string, Experiment>>({});
  const [history, setHistory] = useState<Experiment[]>([]);
  const [gaps, setGaps] = useState<any>(null);
  const [predictions, setPredictions] = useState<Prediction[]>([]);
  const [loading, setLoading] = useState(false);
  const [killConfirm, setKillConfirm] = useState(false);

  // Fetch active experiments
  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${CHAOS_ENGINE_URL}/experiments/status`);
      if (res.ok) {
        const data = await res.json();
        setExperiments(data.experiments || {});
      }
    } catch (e) { /* silently retry */ }
  }, []);

  // Fetch history
  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch(`${CHAOS_ENGINE_URL}/experiments/history?limit=20`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.history || []);
      }
    } catch (e) { /* silently retry */ }
  }, []);

  // Fetch gaps
  const fetchGaps = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/chaos-ai/gaps`);
      if (res.ok) setGaps(await res.json());
    } catch (e) { /* silently retry */ }
  }, []);

  // Fetch predictions
  const fetchPredictions = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/chaos-ai/predictions`);
      if (res.ok) {
        const data = await res.json();
        setPredictions(data.predictions || []);
      }
    } catch (e) { /* silently retry */ }
  }, []);

  useEffect(() => {
    fetchStatus();
    fetchHistory();
    fetchGaps();
    fetchPredictions();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [fetchStatus, fetchHistory, fetchGaps, fetchPredictions]);

  // Emergency Kill
  const handleKillAll = async () => {
    setLoading(true);
    try {
      await fetch(`${CHAOS_ENGINE_URL}/chaos/kill-all`, { method: 'POST' });
      setKillConfirm(false);
      fetchStatus();
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  // Start GameDay
  const handleGameDay = async () => {
    setLoading(true);
    try {
      await fetch(`${API_BASE}/api/chaos-scheduler/gameday/start`, { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: '{}' });
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  const activeExps = Object.values(experiments).filter((e: Experiment) => e.status === 'running');

  return (
    <div style={{ padding: 24, color: '#E2E8F0', fontFamily: "'Inter', sans-serif" }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 28, fontWeight: 700, color: '#F1F5F9' }}>
            🔬 Security Chaos Engineering
          </h1>
          <p style={{ color: '#94A3B8', margin: '4px 0 0' }}>Autonomous resilience validation platform</p>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <button
            onClick={handleGameDay}
            disabled={loading}
            style={{
              background: 'linear-gradient(135deg, #7C3AED, #6D28D9)', color: '#fff',
              border: 'none', borderRadius: 8, padding: '10px 20px', cursor: 'pointer',
              fontWeight: 600, fontSize: 13,
            }}
          >🎯 Launch GameDay</button>
          <button
            onClick={() => setKillConfirm(true)}
            style={{
              background: '#DC2626', color: '#fff',
              border: 'none', borderRadius: 8, padding: '10px 20px', cursor: 'pointer',
              fontWeight: 700, fontSize: 14, boxShadow: '0 0 20px rgba(220,38,38,0.4)',
            }}
          >⚠️ EMERGENCY KILL</button>
        </div>
      </div>

      {/* Kill Confirm Modal */}
      {killConfirm && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)', zIndex: 999,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <div style={{ background: '#1E293B', borderRadius: 16, padding: 32, textAlign: 'center', maxWidth: 400 }}>
            <div style={{ fontSize: 48, marginBottom: 16 }}>🚨</div>
            <h2 style={{ color: '#EF4444', marginBottom: 8 }}>Emergency Kill Switch</h2>
            <p style={{ color: '#94A3B8', marginBottom: 24 }}>This will immediately stop ALL active chaos experiments.</p>
            <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
              <button onClick={handleKillAll} disabled={loading}
                style={{ background: '#DC2626', color: '#fff', border: 'none', borderRadius: 8,
                  padding: '12px 32px', cursor: 'pointer', fontWeight: 700 }}>
                CONFIRM KILL ALL
              </button>
              <button onClick={() => setKillConfirm(false)}
                style={{ background: '#374151', color: '#fff', border: 'none', borderRadius: 8,
                  padding: '12px 32px', cursor: 'pointer' }}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tab Nav */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 24, borderBottom: '1px solid #334155', paddingBottom: 8 }}>
        {['dashboard', 'experiments', 'coverage', 'weaknesses', 'gaps', 'gameday'].map((tab: string) => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            style={{
              background: activeTab === tab ? '#3B82F6' : 'transparent',
              color: activeTab === tab ? '#fff' : '#94A3B8',
              border: 'none', borderRadius: 6, padding: '8px 16px', cursor: 'pointer',
              fontWeight: activeTab === tab ? 600 : 400, fontSize: 13, textTransform: 'capitalize',
            }}>{tab}</button>
        ))}
      </div>

      {/* ═══ Dashboard Tab ═══ */}
      {activeTab === 'dashboard' && (
        <div>
          {/* Live Status */}
          <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, marginBottom: 20,
            border: '1px solid #1E293B' }}>
            <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>
              🔴 Live Experiments ({activeExps.length} active)
            </h3>
            {activeExps.length === 0 ? (
              <div style={{ color: '#64748B', textAlign: 'center', padding: 32 }}>
                No active experiments. System is at rest.
              </div>
            ) : activeExps.map((exp: Experiment) => (
              <div key={exp.experiment_id} style={{
                background: '#1E293B', borderRadius: 8, padding: 16, marginBottom: 8,
                border: '1px solid #334155', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              }}>
                <div>
                  <div style={{ fontWeight: 600, color: '#E2E8F0' }}>{exp.name}</div>
                  <div style={{ color: '#94A3B8', fontSize: 12 }}>
                    Target: {exp.target_service} | Blast: {exp.blast_radius}
                  </div>
                </div>
                <StatusBadge status={exp.status} />
              </div>
            ))}
          </div>

          {/* Resilience Metrics */}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 20 }}>
            <MetricCard label="Active Experiments" value={activeExps.length} target="N/A" met={true} />
            <MetricCard label="MITRE Coverage" value={`${gaps?.coverage_pct || 0}%`} target=">80%" met={(gaps?.coverage_pct || 0) >= 80} />
            <MetricCard label="Untested TTPs" value={gaps?.untested_ttps || 0} target="0" met={(gaps?.untested_ttps || 0) === 0} />
            <MetricCard label="Total Experiments" value={history.length} target="N/A" met={true} />
          </div>
        </div>
      )}

      {/* ═══ Experiments Tab ═══ */}
      {activeTab === 'experiments' && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, border: '1px solid #1E293B' }}>
          <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>📋 Experiment History</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #334155' }}>
                {['Name', 'Service', 'Status', 'Blast', 'Started'].map((h: string) => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#94A3B8', fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.map((exp: any, i: number) => (
                <tr key={i} style={{ borderBottom: '1px solid #1E293B' }}>
                  <td style={{ padding: '10px 12px', color: '#E2E8F0' }}>{exp.name}</td>
                  <td style={{ padding: '10px 12px', color: '#94A3B8' }}>{exp.target_service}</td>
                  <td style={{ padding: '10px 12px' }}><StatusBadge status={exp.status} /></td>
                  <td style={{ padding: '10px 12px', color: '#94A3B8' }}>{exp.blast_radius}</td>
                  <td style={{ padding: '10px 12px', color: '#64748B', fontSize: 11 }}>
                    {new Date(exp.start_time).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ═══ MITRE Coverage Tab ═══ */}
      {activeTab === 'coverage' && gaps && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, border: '1px solid #1E293B' }}>
          <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>🗺️ MITRE ATT&CK Coverage Matrix</h3>
          <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
            <MetricCard label="Total TTPs" value={gaps.total_mitre_ttps} target="N/A" met={true} />
            <MetricCard label="Tested" value={gaps.tested_ttps} target=">80%" met={gaps.coverage_pct >= 80} />
            <MetricCard label="Coverage" value={`${gaps.coverage_pct}%`} target=">80%" met={gaps.coverage_pct >= 80} />
          </div>
          <h4 style={{ color: '#F59E0B', marginBottom: 12 }}>Recommended Scenarios</h4>
          {(gaps.recommended_scenarios || []).map((s: any, i: number) => (
            <div key={i} style={{
              background: '#1E293B', borderRadius: 8, padding: 12, marginBottom: 8,
              border: '1px solid #F59E0B30',
            }}>
              <div style={{ fontWeight: 600, color: '#F59E0B' }}>{s.mitre_ttp}: {s.name}</div>
              <div style={{ color: '#94A3B8', fontSize: 12 }}>Target: {s.target_service}</div>
            </div>
          ))}
        </div>
      )}

      {/* ═══ Weaknesses Tab ═══ */}
      {activeTab === 'weaknesses' && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, border: '1px solid #1E293B' }}>
          <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>🔥 Weakness Predictions (AI)</h3>
          {predictions.length === 0 ? (
            <div style={{ color: '#64748B', textAlign: 'center', padding: 32 }}>
              Insufficient experiment data for predictions. Run more chaos experiments.
            </div>
          ) : predictions.map((p: Prediction, i: number) => (
            <div key={i} style={{
              background: '#1E293B', borderRadius: 8, padding: 16, marginBottom: 8,
              border: `1px solid ${p.failure_probability > 50 ? '#EF444430' : '#22C55E30'}`,
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <div>
                <div style={{ fontWeight: 600, color: '#E2E8F0' }}>{p.service}</div>
                <div style={{ color: '#94A3B8', fontSize: 12 }}>
                  Last Resilience: {p.last_resilience_score} | Confidence: {p.confidence}%
                </div>
              </div>
              <div style={{
                fontSize: 20, fontWeight: 700,
                color: p.failure_probability > 50 ? '#EF4444' : p.failure_probability > 25 ? '#F59E0B' : '#22C55E',
              }}>{p.failure_probability}%</div>
            </div>
          ))}
        </div>
      )}

      {/* ═══ Gaps Tab ═══ */}
      {activeTab === 'gaps' && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, border: '1px solid #1E293B' }}>
          <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>🛡️ Remediation Tracker</h3>
          <div style={{ color: '#94A3B8', textAlign: 'center', padding: 32 }}>
            Security gaps discovered during chaos experiments will appear here with fix status tracking.
          </div>
        </div>
      )}

      {/* ═══ GameDay Tab ═══ */}
      {activeTab === 'gameday' && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, border: '1px solid #1E293B' }}>
          <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>🎯 GameDay Control Panel</h3>
          <div style={{ display: 'flex', gap: 16, marginBottom: 24 }}>
            <button onClick={handleGameDay} disabled={loading}
              style={{
                background: 'linear-gradient(135deg, #7C3AED, #6D28D9)', color: '#fff',
                border: 'none', borderRadius: 12, padding: '16px 32px', cursor: 'pointer',
                fontWeight: 700, fontSize: 16,
              }}>🚀 Launch Full GameDay</button>
            <button onClick={() => setKillConfirm(true)}
              style={{
                background: '#DC2626', color: '#fff',
                border: 'none', borderRadius: 12, padding: '16px 32px', cursor: 'pointer',
                fontWeight: 700, fontSize: 16, boxShadow: '0 0 30px rgba(220,38,38,0.5)',
              }}>⛔ EMERGENCY STOP</button>
          </div>
          <div style={{ color: '#94A3B8', fontSize: 13, lineHeight: 1.8 }}>
            <p><strong>Pre-GameDay Checklist:</strong></p>
            <ul>
              <li>✅ All services healthy (Prometheus check)</li>
              <li>✅ Guardrails service active and budget available</li>
              <li>✅ Rollback mechanisms verified</li>
              <li>✅ Incident response team notified</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

export default ChaosEngineering;
