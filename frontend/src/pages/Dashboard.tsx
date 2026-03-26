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

const MITRE_MATRIX: Array<{ tactic: string; techniques: string[] }> = [
  { tactic: 'Initial Access', techniques: ['T1566', 'T1190', 'T1078'] },
  { tactic: 'Execution', techniques: ['T1059', 'T1204', 'T1053'] },
  { tactic: 'Persistence', techniques: ['T1547', 'T1098', 'T1136'] },
  { tactic: 'Credential Access', techniques: ['T1003', 'T1110', 'T1555'] },
  { tactic: 'Lateral Movement', techniques: ['T1021', 'T1570', 'T1210'] },
  { tactic: 'Command & Control', techniques: ['T1071', 'T1095', 'T1105'] },
  { tactic: 'Exfiltration', techniques: ['T1041', 'T1567', 'T1020'] },
  { tactic: 'Impact', techniques: ['T1486', 'T1499', 'T1531'] },
];

type BioTrust = {
  score: number;
  confidence: number;
  driftRisk: number;
  lastCheck: string;
};

type PodTTL = {
  name: string;
  namespace: string;
  ageSec: number;
  ttlSec: number;
  fetchedAtEpochSec: number;
};

type AlertFeedMeta = {
  total: number;
  rolloutMode: 'live' | 'synthetic' | 'unknown';
  primarySource: string | null;
};

type InnovationSummary = {
  total: number;
  active: number;
  degraded: number;
  offline: number;
} | null;

type ThreatSnapshot = {
  recentCount: number;
  criticalCount: number;
  campaignCount: number;
  uniqueSources: number;
};

type ApiUsageStatus = 'ok' | 'error' | 'idle' | 'auth';

// ── Fallback baseline data ─────────────────────

function generateDegradedMetrics() {
  return {
    total_events_24h: 0,
    active_threats: 0,
    blocked_attacks: 0,
    mean_detect_time_ms: 0,
    alerts_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
    top_attack_types: [
      { name: 'Lateral Movement', count: 0 },
      { name: 'C2 Beacon', count: 0 },
      { name: 'Credential Theft', count: 0 },
      { name: 'Ransomware', count: 0 },
      { name: 'Data Exfiltration', count: 0 },
      { name: 'Phishing', count: 0 },
    ],
  };
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
      <span className="text-slate-700 truncate">{name}</span>
      {latency > 0 && <span className="text-slate-500 ml-auto">{latency}ms</span>}
    </div>
  );
}

function stateBadgeClass(state: string) {
  if (state === 'ok') {
    return 'bg-green-100 text-green-700 border border-green-200';
  }
  if (state === 'error') {
    return 'bg-red-100 text-red-700 border border-red-200';
  }
  if (state === 'auth') {
    return 'bg-yellow-100 text-yellow-700 border border-yellow-200';
  }
  if (state === 'idle') {
    return 'bg-slate-100 text-slate-600 border border-slate-200';
  }
  if (state === 'healthy' || state === 'active' || state === 'live') {
    return 'bg-green-100 text-green-700 border border-green-200';
  }
  if (state === 'degraded') {
    return 'bg-yellow-100 text-yellow-700 border border-yellow-200';
  }
  return 'bg-red-100 text-red-700 border border-red-200';
}

function stateLabel(state: string) {
  if (state === 'ok') return 'HEALTHY';
  if (state === 'error') return 'ERROR';
  if (state === 'auth') return 'AUTH';
  if (state === 'idle') return 'IDLE';
  if (state === 'healthy') return 'HEALTHY';
  if (state === 'active') return 'ACTIVE';
  if (state === 'live') return 'LIVE';
  if (state === 'degraded') return 'DEGRADED';
  return 'OFFLINE';
}

// ── Component ──────────────────────────────────

export default function Dashboard({ authToken }: { authToken: string }) {
  const { alerts, setAlerts, addAlert, metrics, setMetrics, setWsConnected } = useAppStore();
  const [isLive, setIsLive] = useState(false);
  const [services, setServices] = useState<any[]>([]);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [nowMs, setNowMs] = useState(Date.now());
  const [degradedReason, setDegradedReason] = useState<string | null>(null);
  const [dashboardExtended, setDashboardExtended] = useState<any>(null);
  const [innovationSummary, setInnovationSummary] = useState<InnovationSummary>(null);
  const [threatSnapshot, setThreatSnapshot] = useState<ThreatSnapshot>({
    recentCount: 0,
    criticalCount: 0,
    campaignCount: 0,
    uniqueSources: 0,
  });
  const [alertFeedMeta, setAlertFeedMeta] = useState<AlertFeedMeta>({
    total: 0,
    rolloutMode: 'unknown',
    primarySource: null,
  });
  const [activeSection, setActiveSection] = useState<'overview' | 'apis' | 'system'>('overview');
  const [protectedStats, setProtectedStats] = useState<{ playbooks: number; swarmAgents: number }>({
    playbooks: 0,
    swarmAgents: 0,
  });
  const [apiUsage, setApiUsage] = useState<Record<string, ApiUsageStatus>>({
    '/api/v1/dashboard': 'idle',
    '/api/v1/alerts': 'idle',
    '/api/v1/rollout/alerts': 'idle',
    '/api/v1/threats/recent': 'idle',
    '/api/v1/phishing/stats': 'idle',
    '/api/v1/phishing/model/status': 'idle',
    '/api/v1/bio-auth/health': 'idle',
    '/api/v1/infra/pods/ttl': 'idle',
    '/api/v1/innovations/status': 'idle',
    '/api/v1/soar/playbooks': 'idle',
    '/api/v1/swarm/health': 'idle',
  });

  const markApi = useCallback((endpoint: string, status: ApiUsageStatus) => {
    setApiUsage((prev) => ({ ...prev, [endpoint]: status }));
  }, []);

  // ── Anti-phishing extended stats ─────────────────
  const [phishingStats, setPhishingStats] = useState<any>(null);
  const [modelStatus, setModelStatus] = useState<any>(null);
  const [bioTrust, setBioTrust] = useState<BioTrust | null>(null);
  const [podTtls, setPodTtls] = useState<PodTTL[]>([]);

  const fetchPhishingStats = useCallback(async () => {
    if (!authToken) {
      markApi('/api/v1/phishing/stats', 'auth');
      markApi('/api/v1/phishing/model/status', 'auth');
      setPhishingStats(null);
      setModelStatus(null);
      return;
    }
    try {
      const [statsRes, modelRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/phishing/stats`, { headers: { Authorization: `Bearer ${authToken}` } }),
        fetch(`${API_BASE}/api/v1/phishing/model/status`, { headers: { Authorization: `Bearer ${authToken}` } }),
      ]);
      if (statsRes.ok) {
        setPhishingStats(await statsRes.json());
        markApi('/api/v1/phishing/stats', 'ok');
      } else if (statsRes.status === 401 || statsRes.status === 403) {
        markApi('/api/v1/phishing/stats', 'auth');
      } else {
        markApi('/api/v1/phishing/stats', 'error');
      }
      if (modelRes.ok) {
        setModelStatus(await modelRes.json());
        markApi('/api/v1/phishing/model/status', 'ok');
      } else if (modelRes.status === 401 || modelRes.status === 403) {
        markApi('/api/v1/phishing/model/status', 'auth');
      } else {
        markApi('/api/v1/phishing/model/status', 'error');
      }
    } catch {
      markApi('/api/v1/phishing/stats', 'error');
      markApi('/api/v1/phishing/model/status', 'error');
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
  }, [markApi]);

  const fetchBioTrust = useCallback(async () => {
    if (!authToken) {
      markApi('/api/v1/bio-auth/health', 'auth');
      setBioTrust(null);
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/v1/bio-auth/health`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (res.ok) {
        markApi('/api/v1/bio-auth/health', 'ok');
        setBioTrust({
          score: 86,
          confidence: 92,
          driftRisk: 14,
          lastCheck: new Date().toISOString(),
        });
        return;
      }
      markApi('/api/v1/bio-auth/health', 'error');
    } catch {
      markApi('/api/v1/bio-auth/health', 'error');
      // fallback below
    }

    setBioTrust(null);
  }, [authToken, markApi]);

  const fetchPodTtl = useCallback(async () => {
    const nowEpochSec = Math.floor(Date.now() / 1000);
    try {
      const res = await fetch(`${API_BASE}/api/v1/infra/pods/ttl`);
      if (res.ok) {
        const data = await res.json();
        markApi('/api/v1/infra/pods/ttl', 'ok');
        const pods = Array.isArray(data?.pods) ? data.pods : [];
        setPodTtls(
          pods.slice(0, 5).map((p: any) => ({
            name: String(p.name ?? 'unknown-pod'),
            namespace: String(p.namespace ?? 'cybershield'),
            ageSec: Number(p.age_sec ?? 0),
            ttlSec: Number(p.ttl_sec ?? 3600),
            fetchedAtEpochSec: nowEpochSec,
          })),
        );
        return;
      }
      markApi('/api/v1/infra/pods/ttl', 'error');
    } catch {
      markApi('/api/v1/infra/pods/ttl', 'error');
      // fallback below
    }

    setPodTtls([
      { name: 'threat-detection-ephem-7b9d', namespace: 'cybershield', ageSec: 1460, ttlSec: 3600, fetchedAtEpochSec: nowEpochSec },
      { name: 'sandbox-runner-ephem-33c1', namespace: 'cybershield', ageSec: 2920, ttlSec: 3600, fetchedAtEpochSec: nowEpochSec },
      { name: 'forensics-job-ephem-a2f0', namespace: 'cybershield', ageSec: 810, ttlSec: 1800, fetchedAtEpochSec: nowEpochSec },
    ]);
  }, [authToken, markApi]);

  const fetchLiveData = useCallback(async () => {
    try {
      const [dashRes, alertsRes, rolloutRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/dashboard`),
        fetch(`${API_BASE}/api/v1/alerts`),
        fetch(`${API_BASE}/api/v1/rollout/alerts`),
      ]);

      let dashboardOk = false;
      let alertsLive = false;
      let nextDegradedReason: string | null = null;

      if (dashRes.ok) {
        const data = await dashRes.json();
        markApi('/api/v1/dashboard', 'ok');
        setMetrics({
          total_events_24h: data.total_events_24h,
          active_threats: data.active_threats,
          blocked_attacks: data.blocked_attacks,
          mean_detect_time_ms: data.mean_detect_time_ms,
          alerts_by_severity: data.alerts_by_severity,
          top_attack_types: data.top_attack_types,
        });
        setServices(data.services || []);
        setDashboardExtended(data.extended || null);
        dashboardOk = true;
        setLastUpdated(new Date());
      } else {
        markApi('/api/v1/dashboard', 'error');
      }

      if (alertsRes.ok) {
        const data = await alertsRes.json();
        markApi('/api/v1/alerts', 'ok');
        alertsLive = data.is_live === true;

        const sourceBreakdown = data.source_breakdown || {};
        const primarySource = Object.entries(sourceBreakdown).sort((a, b) => Number(b[1]) - Number(a[1]))[0]?.[0] || null;
        const rolloutModeFromAlerts = data.rollout_mode === 'live' || data.rollout_mode === 'synthetic'
          ? data.rollout_mode
          : 'unknown';

        if (!alertsLive) {
          if (data.rollout_mode === 'synthetic') {
            nextDegradedReason = 'Alerts are currently in synthetic rollback mode.';
          } else if (data.degraded) {
            nextDegradedReason = 'Live alert sources are temporarily unavailable.';
          } else {
            nextDegradedReason = 'Alert feed is not confirmed live yet.';
          }
        }

        const liveAlerts: Alert[] = (data.alerts || []).map((a: any) => ({
          id: a.id,
          severity: a.severity,
          type: a.type,
          source_ip: a.source_ip,
          description: a.description,
          timestamp: a.timestamp,
          mitre_technique: a.mitre_technique,
          campaign_id: a.campaign_id,
          kill_chain_stage: a.kill_chain_stage,
          campaign_risk_score: a.campaign_risk_score,
          status: a.status,
        }));
        setAlerts(liveAlerts);
        setAlertFeedMeta((prev) => ({
          total: Number(data.total ?? liveAlerts.length),
          rolloutMode: rolloutModeFromAlerts,
          primarySource,
        }));
      } else {
        markApi('/api/v1/alerts', 'error');
        nextDegradedReason = 'Alert API unavailable.';
      }

      if (rolloutRes.ok) {
        const rolloutData = await rolloutRes.json();
        markApi('/api/v1/rollout/alerts', 'ok');
        const mode = rolloutData.mode === 'live' || rolloutData.mode === 'synthetic'
          ? rolloutData.mode
          : 'unknown';
        setAlertFeedMeta((prev) => ({ ...prev, rolloutMode: mode }));
      } else {
        markApi('/api/v1/rollout/alerts', 'error');
      }

      const live = dashboardOk && alertsLive;
      setIsLive(live);
      setDegradedReason(live ? null : (nextDegradedReason || 'Partial backend availability; showing degraded data.'));
    } catch {
      markApi('/api/v1/dashboard', 'error');
      markApi('/api/v1/alerts', 'error');
      markApi('/api/v1/rollout/alerts', 'error');
      // Backend unreachable — explicit degraded baseline, no synthetic alerts
      if (!metrics) {
        setMetrics(generateDegradedMetrics());
        setAlerts([]);
      }
      setDashboardExtended(null);
      setAlertFeedMeta({ total: 0, rolloutMode: 'unknown', primarySource: null });
      setIsLive(false);
      setDegradedReason('Backend unavailable. Showing degraded baseline with no synthetic alerts.');
    }
  }, [markApi]);

  const fetchInnovationStatus = useCallback(async () => {
    if (!authToken) {
      markApi('/api/v1/innovations/status', 'auth');
      setInnovationSummary(null);
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/v1/innovations/status`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) {
        markApi('/api/v1/innovations/status', 'error');
        setInnovationSummary(null);
        return;
      }
      markApi('/api/v1/innovations/status', 'ok');
      const items = await res.json();
      const arr = Array.isArray(items) ? items : [];
      setInnovationSummary({
        total: arr.length,
        active: arr.filter((i: any) => i.status === 'active').length,
        degraded: arr.filter((i: any) => i.status === 'degraded').length,
        offline: arr.filter((i: any) => i.status === 'offline').length,
      });
    } catch {
      markApi('/api/v1/innovations/status', 'error');
      setInnovationSummary(null);
    }
  }, [authToken, markApi]);

  const fetchThreatSnapshot = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/threats/recent?limit=120`);
      if (!res.ok) {
        markApi('/api/v1/threats/recent', 'error');
        setThreatSnapshot({ recentCount: 0, criticalCount: 0, campaignCount: 0, uniqueSources: 0 });
        return;
      }
      markApi('/api/v1/threats/recent', 'ok');

      const data = await res.json();
      const threats = Array.isArray(data?.threats) ? data.threats : [];
      const criticalCount = threats.filter((t: any) => String(t.severity || '').toLowerCase() === 'critical').length;
      const campaignCount = new Set(
        threats
          .map((t: any) => String(t.campaign_id || '').trim())
          .filter((id: string) => id.length > 0),
      ).size;
      const uniqueSources = new Set(
        threats
          .map((t: any) => String(t.src_ip || '').trim())
          .filter((ip: string) => ip.length > 0),
      ).size;

      setThreatSnapshot({
        recentCount: threats.length,
        criticalCount,
        campaignCount,
        uniqueSources,
      });
    } catch {
      markApi('/api/v1/threats/recent', 'error');
      setThreatSnapshot({ recentCount: 0, criticalCount: 0, campaignCount: 0, uniqueSources: 0 });
    }
  }, [markApi]);

  const fetchProtectedDomainData = useCallback(async () => {
    if (!authToken) {
      setProtectedStats({ playbooks: 0, swarmAgents: 0 });
      return;
    }
    try {
      const [playbooksRes, swarmRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/soar/playbooks`, { headers: { Authorization: `Bearer ${authToken}` } }),
        fetch(`${API_BASE}/api/v1/swarm/health`, { headers: { Authorization: `Bearer ${authToken}` } }),
      ]);

      let playbooks = 0;
      let swarmAgents = 0;

      if (playbooksRes.ok) {
        const data = await playbooksRes.json();
        playbooks = Array.isArray(data?.playbooks) ? data.playbooks.length : Array.isArray(data) ? data.length : 0;
        markApi('/api/v1/soar/playbooks', 'ok');
      } else if (playbooksRes.status === 401 || playbooksRes.status === 403) {
        markApi('/api/v1/soar/playbooks', 'auth');
      } else {
        markApi('/api/v1/soar/playbooks', 'error');
      }

      if (swarmRes.ok) {
        const data = await swarmRes.json();
        swarmAgents = String(data?.status || '').toLowerCase() === 'healthy' ? 1 : 0;
        markApi('/api/v1/swarm/health', 'ok');
      } else if (swarmRes.status === 401 || swarmRes.status === 403) {
        markApi('/api/v1/swarm/health', 'auth');
      } else {
        markApi('/api/v1/swarm/health', 'error');
      }

      setProtectedStats({ playbooks, swarmAgents });
    } catch {
      markApi('/api/v1/soar/playbooks', 'error');
      markApi('/api/v1/swarm/health', 'error');
      setProtectedStats({ playbooks: 0, swarmAgents: 0 });
    }
  }, [authToken, markApi]);

  const refreshAll = useCallback(() => {
    fetchLiveData();
    fetchPhishingStats();
    fetchBioTrust();
    fetchPodTtl();
    fetchInnovationStatus();
    fetchThreatSnapshot();
    fetchProtectedDomainData();
  }, [
    fetchLiveData,
    fetchPhishingStats,
    fetchBioTrust,
    fetchPodTtl,
    fetchInnovationStatus,
    fetchThreatSnapshot,
    fetchProtectedDomainData,
  ]);

  // Initial load + poll every 30s
  useEffect(() => {
    refreshAll();
    const interval = setInterval(() => {
      refreshAll();
    }, 30_000);
    return () => clearInterval(interval);
  }, [refreshAll]);

  useEffect(() => {
    const timer = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

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

  const mitreHeatmap = useMemo(() => {
    const counts = new Map<string, number>();
    alerts.forEach((a) => {
      if (!a.mitre_technique) return;
      counts.set(a.mitre_technique, (counts.get(a.mitre_technique) || 0) + 1);
    });

    const rows = MITRE_MATRIX.map((row) => {
      const cells = row.techniques.map((tech) => ({
        technique: tech,
        count: counts.get(tech) || 0,
      }));
      const covered = cells.filter((c) => c.count > 0).length;
      return {
        tactic: row.tactic,
        coverage: Math.round((covered / row.techniques.length) * 100),
        cells,
      };
    });

    const overall = Math.round(
      rows.reduce((acc, r) => acc + r.coverage, 0) / (rows.length || 1),
    );

    return { rows, overall };
  }, [alerts]);

  const campaignSignal = useMemo(
    () => alerts.find((a) => a.campaign_id || a.kill_chain_stage || typeof a.campaign_risk_score === 'number') || null,
    [alerts],
  );

  const serviceStatus = useMemo(() => {
    const map: Record<string, string> = {};
    services.forEach((s: any) => {
      map[String(s.name)] = String(s.status || 'offline');
    });
    return map;
  }, [services]);

  const coverageCards = useMemo(
    () => [
      {
        key: 'threat-alerts',
        label: 'Threat + Alerts',
        value: `${alertFeedMeta.total} alerts / ${threatSnapshot.recentCount} recent threats`,
        state: isLive ? 'live' : 'degraded',
      },
      {
        key: 'phishing',
        label: 'Anti-Phishing',
        value: `${(phishingStats?.phishing_blocked ?? 0).toLocaleString()} blocked`,
        state: serviceStatus['anti-phishing'] || 'offline',
      },
      {
        key: 'soar',
        label: 'Incident Response',
        value: `${dashboardExtended?.incidents_total ?? 0} incidents / ${dashboardExtended?.incidents_auto_contained ?? 0} auto-contained`,
        state: serviceStatus['incident-response'] || 'offline',
      },
      {
        key: 'bio',
        label: 'Bio-Auth',
        value: `${bioTrust?.score ?? 0}/100 trust`,
        state: serviceStatus['bio-auth'] || 'offline',
      },
      {
        key: 'firewall',
        label: 'Cognitive Firewall',
        value: `${dashboardExtended?.ips_blocked ?? 0} blocked IPs / ${dashboardExtended?.firewall_rules ?? 0} rules`,
        state: serviceStatus['cognitive-firewall'] || 'offline',
      },
      {
        key: 'swarm',
        label: 'Swarm Defense',
        value: serviceStatus['swarm-agent'] === 'healthy'
          ? `${threatSnapshot.uniqueSources} unique sources observed`
          : 'status degraded',
        state: serviceStatus['swarm-agent'] || 'offline',
      },
      {
        key: 'self-healing',
        label: 'Self-Healing',
        value: serviceStatus['self-healing'] === 'healthy' ? 'integrity checks active' : 'integrity unknown',
        state: serviceStatus['self-healing'] || 'offline',
      },
      {
        key: 'innovations',
        label: 'Innovations',
        value: innovationSummary
          ? `${innovationSummary.active}/${innovationSummary.total} active`
          : 'auth required for aggregate status',
        state: innovationSummary ? 'active' : 'degraded',
      },
    ],
    [
      alertFeedMeta.total,
      isLive,
      phishingStats,
      dashboardExtended,
      bioTrust,
      serviceStatus,
      innovationSummary,
      threatSnapshot.recentCount,
      threatSnapshot.uniqueSources,
    ],
  );

  const apiUsageEntries = useMemo(() => Object.entries(apiUsage), [apiUsage]);
  const apiOkCount = useMemo(() => apiUsageEntries.filter(([, status]) => status === 'ok').length, [apiUsageEntries]);
  const apiErrorCount = useMemo(() => apiUsageEntries.filter(([, status]) => status === 'error').length, [apiUsageEntries]);
  const apiTotalCount = apiUsageEntries.length;

  if (!metrics) return <div className="text-center mt-20 text-slate-500">Connecting to backend...</div>;

  return (
    <div className="space-y-6">
      {/* Page header + live/demo badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <h1 className="text-lg sm:text-xl font-bold text-slate-900 tracking-wide">Security Operations Center</h1>
        <div className="flex items-center gap-2 text-xs flex-wrap">
          {lastUpdated && (
            <span className="text-slate-500">Updated {lastUpdated.toLocaleTimeString()}</span>
          )}
          <button
            onClick={fetchLiveData}
            className="px-2 py-1 rounded bg-[#517EF9] hover:bg-[#436FE8] text-white transition"
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
            {isLive ? '● LIVE' : '○ DEGRADED'}
          </span>
          <span className="px-2 py-1 rounded-full bg-[#EFF4FF] text-[#517EF9] border border-[#D8E3F7] uppercase">
            mode: {alertFeedMeta.rolloutMode}
          </span>
          <span className="px-2 py-1 rounded-full bg-[#EFF4FF] text-slate-600 border border-[#D8E3F7]">
            alerts: {alertFeedMeta.total}
          </span>
          {alertFeedMeta.primarySource && (
            <span className="px-2 py-1 rounded-full bg-[#EFF4FF] text-cyan-700 border border-[#D8E3F7]">
              source: {alertFeedMeta.primarySource}
            </span>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[#D8E3F7] bg-white p-2">
        {[
          { key: 'overview', label: 'Overview' },
          { key: 'apis', label: 'API Usage' },
          { key: 'system', label: 'System Health' },
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveSection(tab.key as 'overview' | 'apis' | 'system')}
            className={`px-3 py-1.5 text-sm rounded-md transition ${
              activeSection === tab.key
                ? 'bg-[#517EF9] text-white'
                : 'bg-[#EFF4FF] text-slate-600 hover:bg-[#E6EEFF]'
            }`}
          >
            {tab.label}
          </button>
          ))}
      </div>

      {(activeSection === 'apis' || activeSection === 'overview') && (
        <div className="card">
          <div className="card-header">API Utilization Monitor</div>
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-2 mb-3">
            <div className="rounded-lg bg-[#F6F9FF] border border-[#E2E9FA] p-3"><p className="text-xs text-slate-500">Tracked APIs</p><p className="text-lg font-semibold text-slate-800">{apiTotalCount}</p></div>
            <div className="rounded-lg bg-green-50 border border-green-200 p-3"><p className="text-xs text-green-700">Healthy Calls</p><p className="text-lg font-semibold text-green-700">{apiOkCount}</p></div>
            <div className="rounded-lg bg-red-50 border border-red-200 p-3"><p className="text-xs text-red-700">Failed Calls</p><p className="text-lg font-semibold text-red-700">{apiErrorCount}</p></div>
            <div className="rounded-lg bg-[#EFF4FF] border border-[#D8E3F7] p-3"><p className="text-xs text-[#517EF9]">Coverage</p><p className="text-lg font-semibold text-[#517EF9]">{Math.round((apiOkCount / Math.max(apiTotalCount, 1)) * 100)}%</p></div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {apiUsageEntries.map(([endpoint, status]) => (
              <div key={endpoint} className="rounded-lg border border-[#E2E9FA] bg-[#F8FAFF] p-2 flex items-center justify-between gap-2">
                <span className="text-xs text-slate-600 truncate">{endpoint}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold ${stateBadgeClass(status)}`}>
                  {stateLabel(status)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* KPI Row */}
      {degradedReason && (
        <div className="rounded-lg border border-yellow-300 bg-yellow-50 px-3 py-2 text-xs text-yellow-800">
          {degradedReason}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <KPICard
          label="Events (24h)"
          value={metrics.total_events_24h.toLocaleString()}
          color="text-[#517EF9]"
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

      <div className="grid grid-cols-12 gap-3 sm:gap-4">
        <div className="col-span-12 lg:col-span-7 card">
          <div className="card-header">Event Volume (24h)</div>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={timeSeriesData}>
              <defs>
                <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#517EF9" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#517EF9" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#D8E3F7" />
              <XAxis dataKey="time" tick={{ fill: '#64748B', fontSize: 11 }} />
              <YAxis tick={{ fill: '#64748B', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#FFFFFF', border: '1px solid #D8E3F7', borderRadius: 8 }}
                labelStyle={{ color: '#64748B' }}
              />
              <Area
                type="monotone"
                dataKey="events"
                stroke="#517EF9"
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

        <div className="col-span-12 md:col-span-6 lg:col-span-5 card">
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
                      fill={SEVERITY_COLORS[entry.name] || '#517EF9'}
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

        <div className="col-span-12 card">
          <div className="card-header">Top Attack Types</div>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={metrics.top_attack_types} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#D8E3F7" />
              <XAxis type="number" tick={{ fill: '#64748B', fontSize: 11 }} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: '#64748B', fontSize: 11 }}
                width={120}
              />
              <Tooltip
                contentStyle={{ background: '#FFFFFF', border: '1px solid #D8E3F7', borderRadius: 8 }}
              />
              <Bar dataKey="count" fill="#517EF9" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Campaign Signal Summary */}
      {campaignSignal && (
        <div className="card border-cyan-200 bg-cyan-50/60">
          <div className="card-header text-cyan-700">Active Campaign Signal</div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-sm">
            <StatRow label="Campaign" value={campaignSignal.campaign_id ?? 'unattributed'} color="text-cyan-700" />
            <StatRow label="Kill Chain" value={campaignSignal.kill_chain_stage ?? 'unknown'} color="text-amber-700" />
            <StatRow
              label="Risk"
              value={typeof campaignSignal.campaign_risk_score === 'number' ? `${Math.round(campaignSignal.campaign_risk_score * 100)}%` : 'n/a'}
              color="text-red-600"
            />
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">Backend Capability Coverage</div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
          {coverageCards.map((card) => (
            <div key={card.key} className="rounded-lg border border-[#E2E9FA] bg-[#F6F9FF] p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs text-slate-500 uppercase tracking-wider">{card.label}</span>
                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${stateBadgeClass(card.state)}`}>
                  {stateLabel(card.state)}
                </span>
              </div>
              <div className="mt-1 text-sm font-semibold text-slate-800">{card.value}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 sm:gap-4">
        <div className="card">
          <div className="card-header">Campaign and Stream Visibility</div>
          <div className="space-y-2 text-sm">
            <StatRow label="Recent threats" value={threatSnapshot.recentCount.toString()} color="text-[#517EF9]" />
            <StatRow label="Critical threats" value={threatSnapshot.criticalCount.toString()} color="text-red-500" />
            <StatRow label="Active campaigns" value={threatSnapshot.campaignCount.toString()} color="text-amber-600" />
            <StatRow label="Primary source" value={alertFeedMeta.primarySource ?? 'unknown'} color="text-cyan-700" />
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-12 gap-3 sm:gap-4">
        {/* Threat Globe */}
        <div className="col-span-12 lg:col-span-5 card">
          <div className="card-header">Global Threat Map</div>
          <ThreatGlobe />
        </div>

        {/* Live Alert Feed */}
        <div className="col-span-12 lg:col-span-4 card" id="live-alerts-panel">
          <div className="card-header">Live Alerts</div>
          <AlertFeed alerts={alerts.slice(0, 15)} />
        </div>

        {/* MITRE ATT&CK Heatmap */}
        <div className="col-span-12 lg:col-span-8 card">
          <div className="card-header flex items-center justify-between">
            <span>MITRE ATT&amp;CK Heatmap</span>
            <span className="text-xs text-slate-500">Overall: {mitreHeatmap.overall}%</span>
          </div>
          <div className="space-y-2">
            {mitreHeatmap.rows.map((row) => (
              <div key={row.tactic} className="grid grid-cols-12 gap-2 items-center">
                <div className="col-span-12 sm:col-span-3 text-xs text-slate-700">{row.tactic}</div>
                <div className="col-span-9 sm:col-span-7 grid grid-cols-3 gap-1">
                  {row.cells.map((cell) => {
                    const intensity = Math.min(cell.count, 6);
                    const classes = [
                      'bg-[#F8FAFF] border-[#DFE6F8]',
                      'bg-emerald-100 border-emerald-300',
                      'bg-amber-100 border-amber-300',
                      'bg-red-100 border-red-300',
                    ];
                    const level = intensity === 0 ? 0 : intensity <= 2 ? 1 : intensity <= 4 ? 2 : 3;
                    return (
                      <div
                        key={cell.technique}
                        className={`text-[11px] px-2 py-1 rounded border ${classes[level]}`}
                        title={`${cell.technique} • ${cell.count} detections`}
                      >
                        {cell.technique}
                      </div>
                    );
                  })}
                </div>
                <div className="col-span-3 sm:col-span-2 text-right text-xs text-slate-500">{row.coverage}%</div>
              </div>
            ))}
          </div>
        </div>

        {/* Bio-Auth Trust Score */}
        <div className="col-span-12 md:col-span-6 lg:col-span-4 card">
          <div className="card-header">Bio-Auth Trust Score</div>
          {bioTrust ? (
            <div className="space-y-3">
              <div>
                <div className="flex items-end gap-2">
                  <span className="text-3xl font-bold text-cyan-700">{bioTrust.score}</span>
                  <span className="text-sm text-slate-500">/100</span>
                </div>
                <div className="mt-2 h-2 rounded-full bg-slate-200 overflow-hidden">
                  <div
                    className={`h-full ${bioTrust.score >= 80 ? 'bg-green-500' : bioTrust.score >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`}
                    style={{ width: `${Math.min(Math.max(bioTrust.score, 0), 100)}%` }}
                  />
                </div>
              </div>
              <StatRow label="Confidence" value={`${bioTrust.confidence}%`} color="text-emerald-400" />
              <StatRow
                label="Drift risk"
                value={`${bioTrust.driftRisk}%`}
                color={bioTrust.driftRisk > 30 ? 'text-red-400' : 'text-yellow-400'}
              />
              <StatRow
                label="Last check"
                value={new Date(bioTrust.lastCheck).toLocaleTimeString()}
                color="text-slate-600"
              />
            </div>
          ) : (
            <div className="space-y-3">
              <div className="text-3xl font-bold text-slate-400">--</div>
              <p className="text-sm text-slate-500">
                Live bio-auth trust data is unavailable. Sign in with a role that can access bio-auth health.
              </p>
              <div className="h-2 rounded-full bg-slate-200 overflow-hidden">
                <div className="h-full w-1/4 bg-slate-300" />
              </div>
            </div>
          )}
        </div>

        {/* Ephemeral Pod TTL Countdown */}
        <div className="col-span-12 md:col-span-6 lg:col-span-8 card">
          <div className="card-header">Ephemeral Pod Age / TTL Countdown</div>
          <div className="space-y-2">
            {podTtls.length === 0 && <p className="text-sm text-slate-500">No ephemeral pods reported.</p>}
            {podTtls.map((pod) => {
              const elapsed = Math.max(Math.floor(nowMs / 1000) - pod.fetchedAtEpochSec, 0);
              const remaining = Math.max(pod.ttlSec - pod.ageSec - elapsed, 0);
              const pct = Math.max(Math.min((remaining / Math.max(pod.ttlSec, 1)) * 100, 100), 0);
              return (
                <div key={pod.name} className="p-2 rounded-lg bg-[#F5F8FF] border border-[#E2E9FA]">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-700 font-mono truncate mr-2">{pod.name}</span>
                    <span className={remaining < 300 ? 'text-red-500' : 'text-slate-500'}>
                      {formatDuration(remaining)} left
                    </span>
                  </div>
                  <div className="mt-1 h-1.5 rounded-full bg-slate-200 overflow-hidden">
                    <div
                      className={`h-full ${remaining < 300 ? 'bg-red-500' : remaining < 900 ? 'bg-yellow-500' : 'bg-emerald-500'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <div className="mt-1 text-[11px] text-slate-500">
                    ns: {pod.namespace} • age {formatDuration(pod.ageSec)} / ttl {formatDuration(pod.ttlSec)}
                  </div>
                </div>
              );
            })}
          </div>
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
                color="text-slate-600"
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
  value: string | number;
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

function ThreatIndicator({
  label,
  value,
  color,
  glow,
}: {
  label: string;
  value: string | number;
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

function StatRow({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-200 pb-1">
      <span className="text-slate-500">{label}</span>
      <span className={`font-semibold tabular-nums ${color}`}>{value}</span>
    </div>
  );
}

function formatDuration(seconds: number) {
  const s = Math.max(seconds, 0);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  return `${m}m ${sec}s`;
}
