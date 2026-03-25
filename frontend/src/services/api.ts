const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080/api/v1';
const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8080/ws';

// ── REST helpers ───────────────────────────────

async function fetchJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

// ── API functions ──────────────────────────────

export const api = {
  // Metrics
  getMetrics: () => fetchJSON('/metrics/dashboard'),

  // Alerts
  getAlerts: (limit = 100) => fetchJSON(`/alerts?limit=${limit}`),
  updateAlert: (id: string, status: string) =>
    postJSON(`/alerts/${id}/status`, { status }),

  // Threat Hunting
  searchThreats: (query: string) =>
    postJSON('/threat-hunting/search', { query }),
  getThreatGraph: () => fetchJSON('/threat-hunting/graph'),

  // Swarm
  getSwarmAgents: () => fetchJSON('/swarm/agents'),
  getSwarmConsensus: () => fetchJSON('/swarm/consensus'),

  // Dream State
  getDreamReports: () => fetchJSON('/dream/reports'),
  getDreamFindings: (reportId: string) =>
    fetchJSON(`/dream/reports/${reportId}/findings`),

  // Innovations
  getInnovationStatus: () => fetchJSON('/innovations/status'),

  // Bio-Auth
  getBioAuthStats: () => fetchJSON('/bio-auth/stats'),

  // Cognitive Firewall
  getFirewallThreats: () => fetchJSON('/cognitive-firewall/threats'),

  // Self-Healing
  getSelfHealingHealth: () => fetchJSON('/self-healing/health'),

  // Incident Response
  getPlaybooks: () => fetchJSON('/soar/playbooks'),
  executePlaybook: (name: string, context: unknown) =>
    postJSON(`/soar/playbooks/${name}/execute`, context),
};

// ── WebSocket ──────────────────────────────────

export function connectWebSocket(
  onMessage: (data: unknown) => void,
  onConnect?: () => void,
  onDisconnect?: () => void,
): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/events`);

  ws.onopen = () => {
    console.log('[WS] Connected');
    onConnect?.();
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch {
      console.warn('[WS] Invalid message:', event.data);
    }
  };

  ws.onclose = () => {
    console.log('[WS] Disconnected — reconnecting in 3s');
    onDisconnect?.();
    setTimeout(() => connectWebSocket(onMessage, onConnect, onDisconnect), 3000);
  };

  ws.onerror = (err) => {
    console.error('[WS] Error:', err);
  };

  return ws;
}
