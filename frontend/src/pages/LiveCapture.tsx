import React, { useState, useEffect, useRef, useCallback } from 'react';

// ── Types ──────────────────────────────────────────────

interface ThreatAlert {
  event_id:     string;
  timestamp:    string;
  src_ip:       string;
  dst_ip:       string;
  dst_port:     number;
  protocol:     string;
  severity:     string;
  score:        number;
  techniques:   string[];
  mitre_id:     string;
  mitre_name:   string;
  mitre_tactic: string;
  simulated:    boolean;
}

interface CaptureStatus {
  running:          boolean;
  mode?:            string;
  interface?:       string;
  filter?:          string;
  packets_captured?: number;
  packets_per_sec?:  number;
  uptime_s?:         number;
}

interface ProtoDist { [key: string]: number }

// ── Constants ──────────────────────────────────────────

const API  = 'http://localhost:8001';
const WS   = 'ws://localhost:8001/ws/live-alerts';
const MAX_ALERTS = 100;

const SEV_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-green-500/20 text-green-400 border-green-500/30',
};

const SEV_RING: Record<string, string> = {
  CRITICAL: 'border-red-500/40',
  HIGH:     'border-orange-500/40',
  MEDIUM:   'border-yellow-500/40',
  LOW:      'border-green-500/40',
};

// ── Helpers ────────────────────────────────────────────

function fmtTime(iso: string): string {
  try { return new Date(iso).toLocaleTimeString(); } catch { return '—'; }
}
function fmtUptime(s: number): string {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

// ── Alert Card ─────────────────────────────────────────

function AlertCard({ alert }: { alert: ThreatAlert }) {
  const sev = alert.severity?.toUpperCase() || 'LOW';
  return (
    <div className={`border rounded-lg p-3 transition-all animate-in fade-in slide-in-from-top-2 duration-300 ${SEV_RING[sev] || 'border-slate-700/50'} bg-slate-900/60`}>
      <div className="flex items-center justify-between gap-2 mb-2">
        <div className="flex items-center gap-2">
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${SEV_STYLE[sev] || SEV_STYLE['LOW']}`}>
            {sev}
          </span>
          <span className="text-sm font-semibold text-gray-200">{alert.mitre_name || alert.techniques?.[0] || 'Unknown'}</span>
          {alert.simulated && (
            <span className="text-[9px] text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1 rounded">SIM</span>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs text-gray-500 flex-shrink-0">
          <span className="font-mono">{(alert.score * 100).toFixed(0)}%</span>
          <span>{fmtTime(alert.timestamp)}</span>
        </div>
      </div>
      <div className="flex items-center gap-2 text-[11px] font-mono text-gray-400">
        <span className="text-cyan-400">{alert.src_ip || '?'}</span>
        <span className="text-gray-600">→</span>
        <span className="text-rose-400">{alert.dst_ip || '?'}</span>
        {alert.dst_port > 0 && <span className="text-gray-500">:{alert.dst_port}</span>}
        <span className="ml-1 px-1.5 py-0.5 bg-slate-800 rounded text-gray-500">{alert.protocol}</span>
        {alert.mitre_id && (
          <span className="ml-auto px-1.5 py-0.5 bg-purple-900/30 border border-purple-500/20 text-purple-400 rounded">{alert.mitre_id}</span>
        )}
      </div>
      {alert.mitre_tactic && (
        <div className="text-[10px] text-gray-600 mt-1">Tactic: {alert.mitre_tactic}</div>
      )}
    </div>
  );
}

// ── Protocol Bar Chart ─────────────────────────────────

function ProtocolChart({ dist }: { dist: ProtoDist }) {
  const total = Object.values(dist).reduce((s, v) => s + v, 0) || 1;
  const sorted = Object.entries(dist).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const COLORS = ['bg-cyan-500', 'bg-purple-500', 'bg-amber-500', 'bg-green-500', 'bg-rose-500', 'bg-blue-500'];

  return (
    <div className="space-y-2">
      {sorted.map(([proto, count], i) => (
        <div key={proto} className="flex items-center gap-2 text-xs">
          <span className="text-gray-400 w-10 flex-shrink-0 font-mono">{proto}</span>
          <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${COLORS[i % COLORS.length]}`}
              style={{ width: `${(count / total) * 100}%` }}
            />
          </div>
          <span className="text-gray-500 w-8 text-right">{count}</span>
        </div>
      ))}
      {sorted.length === 0 && <div className="text-gray-600 text-xs italic">No traffic yet</div>}
    </div>
  );
}

// ── Main Component ─────────────────────────────────────

export default function LiveCapture() {
  const [alerts, setAlerts]         = useState<ThreatAlert[]>([]);
  const [status, setStatus]         = useState<CaptureStatus>({ running: false });
  const [wsState, setWsState]       = useState<'connecting' | 'connected' | 'offline'>('offline');
  const [protoDist, setProtoDist]   = useState<ProtoDist>({});
  const [threatCount, setThreatCount]       = useState(0);
  const [packetCount, setPacketCount]       = useState(0);
  const [actionLoading, setActionLoading]   = useState(false);
  const wsRef    = useRef<WebSocket | null>(null);
  const feedRef  = useRef<HTMLDivElement>(null);

  // Poll status every 3s
  const fetchStatus = useCallback(async () => {
    try {
      const r = await fetch(`${API}/capture/status`);
      if (r.ok) setStatus(await r.json());
    } catch {}
  }, []);

  useEffect(() => {
    fetchStatus();
    const t = setInterval(fetchStatus, 3000);
    return () => clearInterval(t);
  }, [fetchStatus]);

  // WebSocket connection
  const connectWS = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    setWsState('connecting');
    try {
      const ws = new WebSocket(WS);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsState('connected');
      };

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'ping') return;
          if (msg.type === 'threat') {
            setAlerts(prev => [msg, ...prev].slice(0, MAX_ALERTS));
            setThreatCount(c => c + 1);
            setPacketCount(c => c + 1);
            setProtoDist(prev => ({
              ...prev,
              [msg.protocol || 'UNKNOWN']: (prev[msg.protocol || 'UNKNOWN'] || 0) + 1,
            }));
          }
        } catch {}
      };

      ws.onclose = () => {
        setWsState('offline');
        // Retry after 5s if capture is running
        setTimeout(() => {
          if (status.running) connectWS();
        }, 5000);
      };

      ws.onerror = () => setWsState('offline');
    } catch {
      setWsState('offline');
    }
  }, [status.running]);

  // Also poll /threats/recent as fallback every 5s  
  useEffect(() => {
    if (wsState !== 'connected') {
      const t = setInterval(async () => {
        try {
          const r = await fetch(`${API}/threats/recent?limit=20`);
          if (r.ok) {
            const data = await r.json();
            if (data.threats?.length > 0) {
              setAlerts(prev => {
                const ids = new Set(prev.map((a: ThreatAlert) => a.event_id));
                const newOnes = data.threats.filter((t: ThreatAlert) => !ids.has(t.event_id));
                return [...newOnes, ...prev].slice(0, MAX_ALERTS);
              });
            }
          }
        } catch {}
      }, 5000);
      return () => clearInterval(t);
    }
  }, [wsState]);

  const handleStart = async () => {
    setActionLoading(true);
    try {
      await fetch(`${API}/capture/start`, { method: 'POST' });
      await fetchStatus();
      connectWS();
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    setActionLoading(true);
    try {
      await fetch(`${API}/capture/stop`, { method: 'POST' });
      wsRef.current?.close();
      await fetchStatus();
    } finally {
      setActionLoading(false);
    }
  };

  // Scroll feed to top on new alerts
  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = 0;
  }, [alerts.length]);

  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount     = alerts.filter(a => a.severity === 'HIGH').length;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <span>🎯</span> Live Packet Analysis
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Real-time network anomaly detection · MITRE ATT&CK mapping · WebSocket streaming
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* WS Status */}
          <span className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full border font-semibold ${
            wsState === 'connected'  ? 'border-green-500/30 text-green-400 bg-green-500/10' :
            wsState === 'connecting' ? 'border-yellow-500/30 text-yellow-400 bg-yellow-500/10' :
                                       'border-gray-600 text-gray-500 bg-gray-800/50'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              wsState === 'connected' ? 'bg-green-500 animate-pulse' :
              wsState === 'connecting' ? 'bg-yellow-500 animate-pulse' : 'bg-gray-600'
            }`} />
            {wsState === 'connected' ? 'WS Live' : wsState === 'connecting' ? 'Connecting…' : 'WS Offline'}
          </span>

          {/* Start / Stop */}
          {status.running ? (
            <button
              onClick={handleStop}
              disabled={actionLoading}
              className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm font-semibold transition-all disabled:opacity-50 flex items-center gap-2"
            >
              <span className="w-2 h-2 rounded-sm bg-white inline-block" />
              Stop Capture
            </button>
          ) : (
            <button
              onClick={handleStart}
              disabled={actionLoading}
              className="px-4 py-2 bg-[#6C63FF] hover:bg-[#8881FF] text-white rounded-lg text-sm font-semibold transition-all shadow-lg shadow-[#6C63FF]/20 disabled:opacity-50 flex items-center gap-2"
            >
              <span className="w-2 h-2 rounded-full bg-white animate-pulse inline-block" />
              {actionLoading ? 'Starting…' : 'Start Capture'}
            </button>
          )}
        </div>
      </div>

      {/* Mode badge when running */}
      {status.running && status.mode && (
        <div className={`flex items-center gap-2 text-xs px-3 py-2 rounded-lg border w-fit ${
          status.mode === 'simulated'
            ? 'border-blue-500/30 bg-blue-500/5 text-blue-400'
            : 'border-green-500/30 bg-green-500/5 text-green-400'
        }`}>
          {status.mode === 'simulated' ? '🔵 Simulation mode' : '🟢 Live capture'} on
          <code className="font-mono text-[11px]">{status.interface}</code>
          — filter: <code className="font-mono text-[11px]">{status.filter}</code>
        </div>
      )}

      {/* KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Threats',    value: alertsCount(alerts), color: 'text-red-400' },
          { label: 'Critical',         value: criticalCount,        color: 'text-red-500' },
          { label: 'High',             value: highCount,            color: 'text-orange-400' },
          { label: 'Packets/sec',      value: status.packets_per_sec?.toFixed(1) ?? '0.0', color: 'text-cyan-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="card text-center py-4">
            <div className={`text-2xl font-bold ${color}`}>{value}</div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alert Feed */}
        <div className="lg:col-span-2 card flex flex-col" style={{ minHeight: '520px' }}>
          <div className="card-header flex justify-between items-center">
            <span>⚡ Live Threat Alerts</span>
            <div className="flex items-center gap-2">
              {status.running && (
                <span className="flex items-center gap-1 text-[10px] text-green-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" /> LIVE
                </span>
              )}
              <button
                onClick={() => setAlerts([])}
                className="text-[10px] text-gray-500 hover:text-gray-300 transition-colors uppercase tracking-wider"
              >
                Clear
              </button>
            </div>
          </div>
          <div ref={feedRef} className="flex-1 overflow-y-auto space-y-2 pr-1" style={{ maxHeight: '460px' }}>
            {alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-600">
                <div className="text-4xl mb-3">🎯</div>
                <div className="text-sm">
                  {status.running ? 'Waiting for threats…' : 'Click "Start Capture" to begin'}
                </div>
                <div className="text-xs text-gray-700 mt-1">
                  Runs in simulation mode when Scapy / root access unavailable
                </div>
              </div>
            ) : (
              alerts.map(alert => <AlertCard key={alert.event_id} alert={alert} />)
            )}
          </div>
        </div>

        {/* Right Panel */}
        <div className="space-y-4">
          {/* Capture Status */}
          <div className="card">
            <div className="card-header">📊 Capture Status</div>
            <div className="space-y-2 text-sm">
              {[
                { label: 'Status',    value: status.running ? '🟢 Running' : '⚫ Stopped' },
                { label: 'Mode',      value: status.mode ?? '—' },
                { label: 'Interface', value: status.interface ?? '—' },
                { label: 'Packets',   value: (status.packets_captured ?? 0).toLocaleString() },
                { label: 'Uptime',    value: status.uptime_s ? fmtUptime(status.uptime_s) : '—' },
              ].map(({ label, value }) => (
                <div key={label} className="flex justify-between items-center py-1 border-b border-slate-800/60 last:border-0">
                  <span className="text-gray-500 text-xs uppercase tracking-wider">{label}</span>
                  <span className="text-gray-300 font-mono text-xs">{value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Protocol distribution */}
          <div className="card">
            <div className="card-header">📡 Protocol Distribution</div>
            <ProtocolChart dist={protoDist} />
          </div>

          {/* Severity breakdown */}
          <div className="card">
            <div className="card-header">🎯 Severity Breakdown</div>
            <div className="space-y-2">
              {(['CRITICAL','HIGH','MEDIUM','LOW'] as const).map(sev => {
                const cnt = alerts.filter(a => a.severity === sev).length;
                const pct = alerts.length > 0 ? (cnt / alerts.length) * 100 : 0;
                return (
                  <div key={sev} className="flex items-center gap-2 text-xs">
                    <span className={`w-14 flex-shrink-0 text-right font-mono ${SEV_STYLE[sev].split(' ')[1]}`}>{sev}</span>
                    <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          sev === 'CRITICAL' ? 'bg-red-500' :
                          sev === 'HIGH' ? 'bg-orange-500' :
                          sev === 'MEDIUM' ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="text-gray-500 w-6 text-right">{cnt}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* API reference */}
      <div className="card bg-[#0B1120]">
        <div className="card-header">⚙ Integration Reference</div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
          {[
            { method: 'POST', path: '/capture/start',     desc: 'Start live capture or simulation' },
            { method: 'POST', path: '/capture/stop',      desc: 'Stop capture' },
            { method: 'GET',  path: '/capture/status',    desc: 'Sniffer stats' },
            { method: 'WS',   path: '/ws/live-alerts',    desc: 'Real-time threat stream' },
          ].map(({ method, path, desc }) => (
            <div key={path} className="flex items-start gap-2">
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold flex-shrink-0 ${
                method === 'WS'   ? 'bg-purple-900/40 text-purple-400' :
                method === 'POST' ? 'bg-amber-900/40 text-amber-400' :
                                    'bg-blue-900/40 text-blue-400'
              }`}>{method}</span>
              <div>
                <code className="text-cyan-400">{path}</code>
                <div className="text-gray-600 text-[10px] normal-case">{desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function alertsCount(alerts: ThreatAlert[]): number {
  return alerts.length;
}
