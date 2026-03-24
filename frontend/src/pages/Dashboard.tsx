import React, { useEffect, useMemo, useState, useCallback } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts';
import { useAppStore, Alert } from '../store/useAppStore';
import { connectWebSocket } from '../services/api';
import AlertFeed from '../components/AlertFeed';
import ThreatGlobe from '../components/ThreatGlobe';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#3B82F6',
};

// ── Fallback mock data ─────────────────────────

function generateMockMetrics() {
  return {
    total_events_24h: 2_847_391,
    active_threats: 47,
    blocked_attacks: 1_293,
    mean_detect_time_ms: 12,
    alerts_by_severity: { critical: 8, high: 23, medium: 67, low: 142 },
    top_attack_types: [
      { name: 'Lateral Movement', count: 312 },
      { name: 'C2 Beacon', count: 187 },
      { name: 'Credential Theft', count: 156 },
      { name: 'Ransomware', count: 89 },
      { name: 'Data Exfiltration', count: 74 },
      { name: 'Phishing', count: 201 },
    ],
  };
}

function generateMockAlerts(): Alert[] {
  return Array.from({ length: 30 }, (_, i) => ({
    id: `alert-mock-${i}`,
    severity: (['critical', 'high', 'high', 'medium', 'medium', 'low'] as const)[i % 6],
    type: ['Lateral Movement', 'C2 Beacon', 'Credential Theft', 'Ransomware', 'Data Exfiltration', 'Phishing'][i % 6],
    source_ip: `10.${(i * 17) % 255}.${(i * 31) % 255}.${(i * 7) % 255}`,
    description: `Detected suspicious activity — matches known ${['APT29', 'APT28', 'Lazarus', 'FIN7'][i % 4]} TTPs`,
    timestamp: new Date(Date.now() - i * 4 * 60_000).toISOString(),
    mitre_technique: ['T1021', 'T1071', 'T1003', 'T1486', 'T1041', 'T1566'][i % 6],
    status: 'open',
  }));
}

function generateTimeSeriesData(baseEvents = 90000) {
  const now = Date.now();
  return Array.from({ length: 24 }, (_, i) => ({
    time: new Date(now - (23 - i) * 3600_000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    }),
    events: Math.floor(baseEvents + (Math.sin(i / 3) * baseEvents * 0.15) + Math.random() * 5000),
    blocked: Math.floor(baseEvents * 0.0004 + Math.random() * 20),
  }));
}

// ── Service health badge ───────────────────────

function ServiceBadge({ name, status, latency }: { name: string; status: string; latency: number }) {
  const color = status === 'healthy' ? 'bg-green-500' : status === 'degraded' ? 'bg-yellow-500' : 'bg-red-500';
  return (
    <div className="flex items-center gap-2 text-xs py-1">
      <span className={`w-2 h-2 rounded-full ${color} flex-shrink-0`} />
      <span className="text-gray-300 truncate">{name}</span>
      {latency > 0 && <span className="text-gray-500 ml-auto">{latency}ms</span>}
    </div>
  );
}

// ── Component ──────────────────────────────────

export default function Dashboard() {
  const { alerts, setAlerts, addAlert, metrics, setMetrics, setWsConnected } = useAppStore();
  const [isLive, setIsLive] = useState(false);
  const [services, setServices] = useState<any[]>([]);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  // ── Anti-phishing extended stats ─────────────────
  const [phishingStats, setPhishingStats] = useState<any>(null);
  const [modelStatus, setModelStatus] = useState<any>(null);

  const fetchPhishingStats = useCallback(async () => {
    try {
      const [statsRes, modelRes] = await Promise.all([
        fetch(`${API_BASE}/api/phishing/stats`),
        fetch(`${API_BASE}/api/phishing/model/status`),
      ]);
      if (statsRes.ok) setPhishingStats(await statsRes.json());
      if (modelRes.ok) setModelStatus(await modelRes.json());
    } catch {
      // Provide demo values if backend unavailable
      setPhishingStats({
        emails_analyzed: 18_245,
        urls_analyzed: 9_302,
        phishing_blocked: 4_561,
        voice_analyzed: 872,
        deepfakes_detected: 34,
        psychographic_assessed: 1_203,
        images_analyzed: 456,
        detonations_run: 2_107,
        iocs_enriched: 6_890,
        feedback_submitted: 312,
      });
      setModelStatus({
        model_version: '1.0.0',
        last_retrained: null,
        pending_feedback_count: 312,
        status: 'active',
      });
    }
  }, []);

  const fetchLiveData = useCallback(async () => {
    try {
      const [dashRes, alertsRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/dashboard`),
        fetch(`${API_BASE}/api/v1/alerts`),
      ]);

      if (dashRes.ok) {
        const data = await dashRes.json();
        setMetrics({
          total_events_24h: data.total_events_24h,
          active_threats: data.active_threats,
          blocked_attacks: data.blocked_attacks,
          mean_detect_time_ms: data.mean_detect_time_ms,
          alerts_by_severity: data.alerts_by_severity,
          top_attack_types: data.top_attack_types,
        });
        setServices(data.services || []);
        setIsLive(true);
        setLastUpdated(new Date());
      }

      if (alertsRes.ok) {
        const data = await alertsRes.json();
        const liveAlerts: Alert[] = (data.alerts || []).map((a: any) => ({
          id: a.id,
          severity: a.severity,
          type: a.type,
          source_ip: a.source_ip,
          description: a.description,
          timestamp: a.timestamp,
          mitre_technique: a.mitre_technique,
          status: a.status,
        }));
        setAlerts(liveAlerts);
      }
    } catch {
      // Backend unreachable — use mock data
      if (!metrics) {
        setMetrics(generateMockMetrics());
        setAlerts(generateMockAlerts());
      }
      setIsLive(false);
    }
  }, []);

  // Initial load + poll every 30s
  useEffect(() => {
    fetchLiveData();
    fetchPhishingStats();
    const interval = setInterval(() => {
      fetchLiveData();
      fetchPhishingStats();
    }, 30_000);
    return () => clearInterval(interval);
  }, [fetchLiveData, fetchPhishingStats]);

  // WebSocket connection
  useEffect(() => {
    let ws: WebSocket;
    try {
      ws = connectWebSocket(
        (data: any) => {
          if (data.type === 'alert') addAlert(data.alert);
          if (data.type === 'metrics') setMetrics(data.metrics);
        },
        () => setWsConnected(true),
        () => setWsConnected(false),
      );
    } catch { /* ws not available */ }
    return () => ws?.close();
  }, []);

  const timeSeriesData = useMemo(
    () => generateTimeSeriesData(metrics?.total_events_24h ? metrics.total_events_24h / 24 : 90000),
    [metrics?.total_events_24h],
  );

  const severityPieData = useMemo(() => {
    if (!metrics) return [];
    return Object.entries(metrics.alerts_by_severity)
      .filter(([, v]) => (v as number) > 0)
      .map(([name, value]) => ({ name, value }));
  }, [metrics]);

  if (!metrics) return <div className="text-center mt-20 text-gray-400">Connecting to backend...</div>;

  return (
    <div className="space-y-6">
      {/* Page header + live/demo badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <h1 className="text-lg sm:text-xl font-bold text-white tracking-wide">Security Operations Center</h1>
        <div className="flex items-center gap-2 text-xs flex-wrap">
          {lastUpdated && (
            <span className="text-gray-500">Updated {lastUpdated.toLocaleTimeString()}</span>
          )}
          <button
            onClick={fetchLiveData}
            className="px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-gray-300 transition"
          >
            ↻ Refresh
          </button>
          <span
            className={`px-3 py-1 rounded-full font-semibold uppercase tracking-widest ${
              isLive
                ? 'bg-green-500/20 text-green-400 border border-green-500/40'
                : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40'
            }`}
          >
            {isLive ? '● LIVE' : '○ DEMO'}
          </span>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <KPICard
          label="Events (24h)"
          value={metrics.total_events_24h.toLocaleString()}
          color="text-[#6C63FF]"
        />
        <KPICard
          label="Active Threats"
          value={metrics.active_threats.toString()}
          color="text-red-400"
          glow
        />
        <KPICard
          label="Blocked Attacks"
          value={metrics.blocked_attacks.toLocaleString()}
          color="text-green-400"
        />
        <KPICard
          label="Mean Detect Time"
          value={`${metrics.mean_detect_time_ms}ms`}
          color="text-cyan-400"
        />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-12 gap-3 sm:gap-4">
        {/* Threat Globe */}
        <div className="col-span-12 lg:col-span-5 card">
          <div className="card-header">Global Threat Map</div>
          <ThreatGlobe />
        </div>

        {/* Event Timeline */}
        <div className="col-span-12 lg:col-span-7 card">
          <div className="card-header">Event Volume (24h)</div>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={timeSeriesData}>
              <defs>
                <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6C63FF" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6C63FF" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" tick={{ fill: '#94A3B8', fontSize: 11 }} />
              <YAxis tick={{ fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: 8 }}
                labelStyle={{ color: '#94A3B8' }}
              />
              <Area
                type="monotone"
                dataKey="events"
                stroke="#6C63FF"
                fill="url(#colorEvents)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke="#10B981"
                fill="transparent"
                strokeWidth={1.5}
                strokeDasharray="4 4"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Alert Severity Breakdown */}
        <div className="col-span-12 md:col-span-6 lg:col-span-4 card">
          <div className="card-header">Alert Severity</div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={severityPieData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                dataKey="value"
                paddingAngle={3}
              >
                {severityPieData.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={SEVERITY_COLORS[entry.name] || '#6C63FF'}
                  />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 text-xs">
            {severityPieData.map((s) => (
              <span key={s.name} className="flex items-center gap-1">
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ background: SEVERITY_COLORS[s.name] }}
                />
                {s.name}: {s.value}
              </span>
            ))}
          </div>
        </div>

        {/* Top Attack Types */}
        <div className="col-span-12 md:col-span-6 lg:col-span-4 card">
          <div className="card-header">Top Attack Types</div>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={metrics.top_attack_types} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis type="number" tick={{ fill: '#94A3B8', fontSize: 11 }} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: '#94A3B8', fontSize: 11 }}
                width={120}
              />
              <Tooltip
                contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: 8 }}
              />
              <Bar dataKey="count" fill="#6C63FF" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Live Alert Feed */}
        <div className="col-span-12 lg:col-span-4 card">
          <div className="card-header">Live Alerts</div>
          <AlertFeed alerts={alerts.slice(0, 15)} />
        </div>

        {/* Service Health */}
        {services.length > 0 && (
          <div className="col-span-12 card">
            <div className="card-header">Backend Service Health</div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-x-6 sm:gap-x-8 gap-y-1">
              {services.map((svc: any) => (
                <ServiceBadge
                  key={svc.name}
                  name={svc.name}
                  status={svc.status}
                  latency={svc.latency_ms}
                />
              ))}
            </div>
          </div>
        )}

        {/* ── Phase 1: Social Engineering Panel ──────────── */}
        {phishingStats && (
          <div className="col-span-12 md:col-span-6 lg:col-span-4 card"  id="social-engineering-panel">
            <div className="card-header">🎭 Social Engineering Detection</div>
            <div className="space-y-2 text-sm">
              <StatRow label="Voice samples analyzed" value={phishingStats.voice_analyzed?.toLocaleString() ?? '—'} color="text-purple-400" />
              <StatRow label="Deepfakes detected" value={phishingStats.deepfakes_detected?.toLocaleString() ?? '—'} color="text-red-400" />
              <StatRow label="Images analyzed" value={phishingStats.images_analyzed?.toLocaleString() ?? '—'} color="text-blue-300" />
              <StatRow label="Psychographic profiles assessed" value={phishingStats.psychographic_assessed?.toLocaleString() ?? '—'} color="text-yellow-400" />
            </div>
          </div>
        )}

        {/* ── Phase 2: Sandbox & Threat Intel Panel ──────── */}
        {phishingStats && (
          <div className="col-span-12 md:col-span-6 lg:col-span-4 card" id="sandbox-intel-panel">
            <div className="card-header">🔬 Sandbox &amp; Threat Intel</div>
            <div className="space-y-2 text-sm">
              <StatRow label="URLs detonated" value={phishingStats.detonations_run?.toLocaleString() ?? '—'} color="text-orange-400" />
              <StatRow label="IOCs enriched" value={phishingStats.iocs_enriched?.toLocaleString() ?? '—'} color="text-cyan-400" />
              <StatRow label="Emails analyzed" value={phishingStats.emails_analyzed?.toLocaleString() ?? '—'} color="text-green-400" />
              <StatRow label="Phishing blocked" value={phishingStats.phishing_blocked?.toLocaleString() ?? '—'} color="text-red-400" />
            </div>
          </div>
        )}

        {/* ── Phase 3: Model Health Panel ─────────────────── */}
        {modelStatus && (
          <div className="col-span-12 md:col-span-6 lg:col-span-4 card" id="model-health-panel">
            <div className="card-header">🧠 Phishing Model Health</div>
            <div className="space-y-2 text-sm">
              <StatRow label="Model version" value={modelStatus.model_version ?? '—'} color="text-indigo-400" />
              <StatRow
                label="Last retrained"
                value={modelStatus.last_retrained
                  ? new Date(modelStatus.last_retrained).toLocaleDateString()
                  : 'Never'}
                color="text-gray-300"
              />
              <StatRow
                label="Pending feedback"
                value={(modelStatus.pending_feedback_count ?? phishingStats?.feedback_submitted ?? 0).toLocaleString()}
                color={modelStatus.pending_feedback_count >= 100 ? 'text-yellow-400' : 'text-green-400'}
              />
              <StatRow
                label="Status"
                value={modelStatus.status ?? 'unknown'}
                color={modelStatus.status === 'active' ? 'text-green-400' : 'text-yellow-400'}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Sub-components ─────────────────────────────

function KPICard({
  label,
  value,
  color,
  glow,
}: {
  label: string;
  value: string;
  color: string;
  glow?: boolean;
}) {
  return (
    <div className={`card ${glow ? 'animate-glow' : ''}`}>
      <div className={`metric-value ${color}`}>{value}</div>
      <div className="metric-label">{label}</div>
    </div>
  );
}

function StatRow({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-700 pb-1">
      <span className="text-gray-400">{label}</span>
      <span className={`font-semibold tabular-nums ${color}`}>{value}</span>
    </div>
  );
}
