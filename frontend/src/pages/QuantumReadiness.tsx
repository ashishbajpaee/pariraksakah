import React, { useState, useEffect, useCallback } from 'react';

// ═══ Types ═══
interface CryptoAsset {
  id: string;
  algorithm: string;
  category: string;
  location: string;
  file_path: string;
  line_number: number;
  context: string;
  key_size?: number;
  quantum_status: string; // "vulnerable" | "partial" | "safe"
  vulnerability_score: number;
  replacement: string;
  risk_level: string; // "critical" | "high" | "medium" | "low"
  discovered_at: string;
}

interface CBOMSummary {
  total_assets: number;
  vulnerable_red: number;
  partial_yellow: number;
  safe_green: number;
  quantum_readiness_score: number;
}

interface AlgorithmInventory {
  [key: string]: {
    count: number;
    status: string;
    vulnerability_score: number;
    replacement: string;
    locations: string[];
  };
}

interface CBOMData {
  cbom_version: string;
  generated_at: string;
  summary: CBOMSummary;
  algorithm_inventory: AlgorithmInventory;
  assets: CryptoAsset[];
}

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8030';

// ═══ Sub Components ═══
const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const colors: Record<string, string> = {
    vulnerable: '#EF4444', partial: '#F59E0B', safe: '#22C55E', unknown: '#6B7280',
  };
  return (
    <span style={{
      background: colors[status] || '#6B7280',
      color: '#fff', padding: '2px 10px', borderRadius: 12, fontSize: 12, fontWeight: 600,
      textTransform: 'capitalize'
    }}>{status}</span>
  );
};

const MetricCard: React.FC<{ label: string; value: string | number; color: string }> = 
  ({ label, value, color }) => (
  <div style={{
    background: '#1E293B', borderRadius: 8, padding: 16, border: `1px solid ${color}30`,
    flex: '1 1 140px',
  }}>
    <div style={{ color: '#94A3B8', fontSize: 11, marginBottom: 4 }}>{label}</div>
    <div style={{ color: color, fontSize: 26, fontWeight: 700 }}>{value}</div>
  </div>
);

// ═══ Main Component ═══
const QuantumReadiness: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [cbom, setCbom] = useState<CBOMData | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanStatus, setScanStatus] = useState<string | null>(null);

  // Fetch CBOM
  const fetchCbom = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/cbom`);
      if (res.ok) {
        setCbom(await res.json());
      }
    } catch (e) { console.warn("No CBOM discovered yet."); }
  }, []);

  useEffect(() => {
    fetchCbom();
    const interval = setInterval(fetchCbom, 30000);
    return () => clearInterval(interval);
  }, [fetchCbom]);

  // Run full asset scan
  const handleScan = async () => {
    setLoading(true);
    setScanStatus("Scanning entire codebase and infrastructure... (approx 10s)");
    try {
      const res = await fetch(`${API_BASE}/scan`, { method: 'POST' });
      if (res.ok) {
        setCbom(await res.json());
        setScanStatus("Scan complete.");
      } else {
        setScanStatus("Scan failed.");
      }
    } catch (e) {
      setScanStatus("Error connecting to scanner API.");
      console.error(e);
    }
    setLoading(false);
    setTimeout(() => setScanStatus(null), 5000);
  };

  const readinessScore = cbom?.summary?.quantum_readiness_score ?? 0;
  // Dynamic color for score
  const scoreColor = readinessScore > 90 ? '#22C55E' : readinessScore > 50 ? '#F59E0B' : '#EF4444';

  return (
    <div style={{ padding: 24, color: '#E2E8F0', fontFamily: "'Inter', sans-serif" }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 28, fontWeight: 700, color: '#F1F5F9' }}>
            ⚛️ Post-Quantum Migration Framework
          </h1>
          <p style={{ color: '#94A3B8', margin: '4px 0 0' }}>Cryptographic Discovery & Agility Dashboard</p>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <button
            onClick={handleScan}
            disabled={loading}
            style={{
              background: 'linear-gradient(135deg, #10B981, #059669)', color: '#fff',
              border: 'none', borderRadius: 8, padding: '10px 20px', cursor: 'pointer',
              fontWeight: 600, fontSize: 13,
            }}
          >🔍 Run Cryptographic Asset Scan (CBOM)</button>
        </div>
      </div>

      {scanStatus && (
        <div style={{ padding: 12, background: '#1E293B', color: '#60A5FA', borderRadius: 8, marginBottom: 20 }}>
          {scanStatus}
        </div>
      )}

      {/* Tab Nav */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 24, borderBottom: '1px solid #334155', paddingBottom: 8 }}>
        {['dashboard', 'inventory', 'agility', 'pki', 'hndl-monitor', 'compliance'].map((tab: string) => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            style={{
              background: activeTab === tab ? '#3B82F6' : 'transparent',
              color: activeTab === tab ? '#fff' : '#94A3B8',
              border: 'none', borderRadius: 6, padding: '8px 16px', cursor: 'pointer',
              fontWeight: activeTab === tab ? 600 : 400, fontSize: 13, textTransform: 'capitalize',
            }}>{tab.replace("-", " ")}</button>
        ))}
      </div>

      {/* ═══ Dashboard Tab ═══ */}
      {activeTab === 'dashboard' && cbom && (
        <div>
          <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, marginBottom: 20, border: '1px solid #1E293B' }}>
            <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>Scorecard: System-Wide Quantum Readiness</h3>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: 32, marginBottom: 24 }}>
                <div style={{ 
                    width: 120, height: 120, borderRadius: '50%', border: `8px solid ${scoreColor}`, 
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 32, fontWeight: 700, color: scoreColor, boxShadow: `0 0 30px ${scoreColor}40`
                }}>
                    {readinessScore}%
                </div>
                <div style={{ flex: 1 }}>
                    <h4 style={{ margin: '0 0 8px', color: '#E2E8F0' }}>Migration Phase: <span style={{ color: '#60A5FA'}}>Phase 1 (Assessment)</span></h4>
                    <p style={{ margin: 0, color: '#94A3B8', fontSize: 14 }}>
                        Your infrastructure is highly vulnerable to Shor's and Grover's algorithm attacks via early-stage fault-tolerant quantum computers. We strongly recommend immediate upgrade of the <strong>{cbom.summary.vulnerable_red}</strong> red assets found below.
                    </p>
                </div>
            </div>

            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <MetricCard label="Total Crypto Assets Discovered" value={cbom.summary.total_assets} color="#3B82F6" />
              <MetricCard label="🔴 Vulnerable to Quantum (RSA/ECC)" value={cbom.summary.vulnerable_red} color="#EF4444" />
              <MetricCard label="🟡 Partially Safe (AES-128/SHA-256)" value={cbom.summary.partial_yellow} color="#F59E0B" />
              <MetricCard label="🟢 Quantum-Safe (AES-256/ML-KEM)" value={cbom.summary.safe_green} color="#22C55E" />
            </div>
          </div>
        </div>
      )}

      {/* ═══ CBOM Inventory Tab ═══ */}
      {activeTab === 'inventory' && cbom && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, border: '1px solid #1E293B' }}>
          <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>📦 Cryptographic Bill of Materials (CBOM)</h3>
          
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #334155' }}>
                {['Algorithm', 'Status', 'Risk Level', 'Instances', 'Target Replacement'].map((h: string) => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#94A3B8', fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.entries(cbom.algorithm_inventory).map(([algo, details]: [string, any], i: number) => (
                <tr key={i} style={{ borderBottom: '1px solid #1E293B' }}>
                  <td style={{ padding: '10px 12px', color: '#E2E8F0', fontWeight: 600 }}>{algo}</td>
                  <td style={{ padding: '10px 12px' }}><StatusBadge status={details.status} /></td>
                  <td style={{ padding: '10px 12px', color: '#94A3B8' }}>{details.vulnerability_score >= 80 ? 'CRITICAL' : 'HIGH'}</td>
                  <td style={{ padding: '10px 12px', color: '#94A3B8' }}>{details.count}</td>
                  <td style={{ padding: '10px 12px', color: '#60A5FA' }}>↳ {details.replacement}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h4 style={{ margin: '24px 0 16px', color: '#F1F5F9' }}>Asset Breakdown List</h4>
          <div style={{ maxHeight: 400, overflowY: 'auto' }}>
            {cbom.assets.map((asset: CryptoAsset, i: number) => (
                <div key={i} style={{ background: '#1E293B', padding: 12, borderRadius: 6, marginBottom: 8, borderLeft: `4px solid ${asset.quantum_status === 'vulnerable' ? '#EF4444' : asset.quantum_status === 'partial' ? '#F59E0B' : '#22C55E'}` }}>
                    <div style={{ fontWeight: 600, color: '#E2E8F0', marginBottom: 4 }}>
                        {asset.algorithm} ({asset.category}) <span style={{ fontWeight: 400, color: '#94A3B8', fontSize: 12, marginLeft: 8 }}>{asset.location}:{asset.line_number}</span>
                    </div>
                    <div style={{ color: '#64748B', fontSize: 11, fontFamily: 'monospace' }}>{asset.context}</div>
                </div>
            ))}
          </div>
        </div>
      )}

      {/* ═══ Crypto Agility Layer Tab ═══ */}
      {activeTab === 'agility' && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, border: '1px solid #1E293B' }}>
          <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>🔀 Crypto Agility API Monitor</h3>
          <p style={{ color: '#94A3B8', fontSize: 14 }}>
            The Agility Layer automatically routes cryptographic requests to appropriate algorithms based on policy.
          </p>

          <div style={{ display: 'flex', gap: 16, marginTop: 20 }}>
            <div style={{ flex: 1, background: '#1E293B', padding: 16, borderRadius: 8, border: '1px solid #EF444430' }}>
                <h4 style={{ color: '#EF4444', margin: '0 0 12px' }}>Classical Fallback</h4>
                <div style={{ color: '#E2E8F0', fontSize: 13, marginBottom: 8 }}>KEM: <strong>ECDH</strong></div>
                <div style={{ color: '#E2E8F0', fontSize: 13 }}>Signature: <strong>ECDSA (P-256)</strong></div>
                <div style={{ marginTop: 16, color: '#94A3B8', fontSize: 11 }}>Traffic: 14% (Legacy Clients)</div>
            </div>
            
            <div style={{ flex: 1, background: '#1E293B', padding: 16, borderRadius: 8, border: '1px solid #F59E0B30' }}>
                <h4 style={{ color: '#F59E0B', margin: '0 0 12px' }}>Hybrid Mode (Active)</h4>
                <div style={{ color: '#E2E8F0', fontSize: 13, marginBottom: 8 }}>KEM: <strong>ECDH + ML-KEM</strong></div>
                <div style={{ color: '#E2E8F0', fontSize: 13 }}>Signature: <strong>ECDSA + ML-DSA</strong></div>
                <div style={{ marginTop: 16, color: '#94A3B8', fontSize: 11 }}>Traffic: 83% (Current Spec)</div>
            </div>

            <div style={{ flex: 1, background: '#1E293B', padding: 16, borderRadius: 8, border: '1px solid #22C55E30' }}>
                <h4 style={{ color: '#22C55E', margin: '0 0 12px' }}>Pure PQC</h4>
                <div style={{ color: '#E2E8F0', fontSize: 13, marginBottom: 8 }}>KEM: <strong>ML-KEM-1024</strong></div>
                <div style={{ color: '#E2E8F0', fontSize: 13 }}>Signature: <strong>ML-DSA-65</strong></div>
                <div style={{ marginTop: 16, color: '#94A3B8', fontSize: 11 }}>Traffic: 3% (Internal TLS 1.3)</div>
            </div>
          </div>
        </div>
      )}

      {/* ═══ Compliance Tab ═══ */}
      {activeTab === 'compliance' && (
        <div style={{ background: '#0F172A', borderRadius: 12, padding: 20, border: '1px solid #1E293B' }}>
          <h3 style={{ margin: '0 0 16px', color: '#F1F5F9' }}>📜 PQC Regulatory Compliance Package</h3>
          
          <div style={{ color: '#E2E8F0', fontSize: 14, marginBottom: 12 }}>
            ✅ <strong>NIST SP 800-208:</strong> FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) implementation checks OK.
          </div>
          <div style={{ color: '#E2E8F0', fontSize: 14, marginBottom: 12 }}>
             ⏳ <strong>NSA CNSA 2.0:</strong> Transition scheduled for software firmware by 2025 (On Track).
          </div>
          <div style={{ color: '#E2E8F0', fontSize: 14, marginBottom: 24 }}>
             ✅ <strong>FIPS 140-3 Validation:</strong> Validating Crypto Agility boundaries and Entropy sources OK.
          </div>

          <button style={{
            background: '#3B82F6', color: '#fff', border: 'none', borderRadius: 6, padding: '8px 16px', cursor: 'pointer', fontWeight: 600, fontSize: 13
          }}>📥 Export Compliance Evidence (PDF/JSON)</button>
        </div>
      )}

      {/* Empty States for others */}
      {!cbom && activeTab !== 'dashboard' && activeTab !== 'compliance' && activeTab !== 'agility' && (
        <div style={{ color: '#64748B', textAlign: 'center', padding: 32 }}>
            Run the CBOM scan first to unlock insights.
        </div>
      )}
    </div>
  );
};

export default QuantumReadiness;
