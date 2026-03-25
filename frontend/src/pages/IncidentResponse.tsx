import React, { useState, useMemo } from 'react';

// ── Types ──────────────────────────────────────

interface Playbook {
  name: string;
  trigger: string;
  severity: string;
  steps: number;
  last_run?: string;
}

interface Incident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'contained' | 'resolved';
  playbook: string;
  started_at: string;
  events: IncidentEvent[];
}

interface IncidentEvent {
  timestamp: string;
  action: string;
  actor: string;
  detail: string;
}

// ── Mock Data ──────────────────────────────────

const PLAYBOOKS: Playbook[] = [
  { name: 'ransomware_response', trigger: 'ransomware_detected', severity: 'critical', steps: 6, last_run: '2024-01-15T08:23:00Z' },
  { name: 'lateral_movement', trigger: 'lateral_movement_detected', severity: 'high', steps: 5 },
  { name: 'data_exfiltration', trigger: 'data_exfil_alert', severity: 'critical', steps: 7, last_run: '2024-01-14T16:45:00Z' },
  { name: 'phishing_response', trigger: 'phishing_confirmed', severity: 'medium', steps: 4 },
  { name: 'apt_containment', trigger: 'apt_indicator_match', severity: 'critical', steps: 8 },
  { name: 'insider_threat', trigger: 'ueba_high_risk', severity: 'high', steps: 5, last_run: '2024-01-13T12:00:00Z' },
];

const ACTIVE_INCIDENTS: Incident[] = [
  {
    id: 'INC-2024-0047',
    title: 'Ransomware Detected — Finance Server Cluster',
    severity: 'critical',
    status: 'active',
    playbook: 'ransomware_response',
    started_at: '2024-01-15T08:20:00Z',
    events: [
      { timestamp: '08:20:00', action: 'Alert Triggered', actor: 'System', detail: 'Ransomware signature T1486 detected on fin-srv-03' },
      { timestamp: '08:20:05', action: 'Playbook Started', actor: 'SOAR Engine', detail: 'ransomware_response playbook auto-triggered' },
      { timestamp: '08:20:08', action: 'Team Notified', actor: 'SOAR Engine', detail: 'SOC Team + CISO notified via PagerDuty' },
      { timestamp: '08:20:12', action: 'Host Isolated', actor: 'SOAR Engine', detail: 'fin-srv-03 network isolated at switch level' },
      { timestamp: '08:20:15', action: 'IP Blocked', actor: 'Cognitive FW', detail: '185.220.101.34 blocked — C2 server' },
      { timestamp: '08:21:00', action: 'Forensic Snapshot', actor: 'SOAR Engine', detail: 'Memory dump initiated for fin-srv-03' },
      { timestamp: '08:23:00', action: 'IOC Enriched', actor: 'Threat Intel', detail: 'Hash linked to BlackCat/ALPHV ransomware group' },
    ],
  },
  {
    id: 'INC-2024-0046',
    title: 'Lateral Movement — Engineering Subnet',
    severity: 'high',
    status: 'contained',
    playbook: 'lateral_movement',
    started_at: '2024-01-15T06:10:00Z',
    events: [
      { timestamp: '06:10:00', action: 'Alert Triggered', actor: 'GNN Model', detail: 'Anomalous RDP connections across 4 hosts' },
      { timestamp: '06:10:30', action: 'Swarm Deployed', actor: 'Swarm Agent', detail: '12 hunter agents deployed to engineering subnet' },
      { timestamp: '06:11:00', action: 'Source Identified', actor: 'Swarm Agent', detail: 'Compromised service account svc-deploy-eng' },
      { timestamp: '06:11:30', action: 'Account Disabled', actor: 'SOAR Engine', detail: 'svc-deploy-eng disabled in Active Directory' },
      { timestamp: '06:12:00', action: 'Contained', actor: 'SOC Analyst', detail: 'Network segment quarantined, monitoring continues' },
    ],
  },
];

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
};

const STATUS_STYLES: Record<string, { bg: string; text: string }> = {
  active: { bg: 'bg-red-500/10', text: 'text-red-400' },
  contained: { bg: 'bg-yellow-500/10', text: 'text-yellow-400' },
  resolved: { bg: 'bg-green-500/10', text: 'text-green-400' },
};

// ── Component ──────────────────────────────────

export default function IncidentResponse() {
  const [selectedIncident, setSelectedIncident] = useState<Incident>(ACTIVE_INCIDENTS[0]);
  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState<{ role: string; text: string }[]>([
    { role: 'system', text: 'Parirakṣakaḥ Incident Copilot ready. Ask me about active incidents, playbook status, or recommended actions.' },
  ]);

  const handleSendChat = () => {
    if (!chatInput.trim()) return;
    const userMsg = chatInput.trim();
    setChatMessages((prev) => [...prev, { role: 'user', text: userMsg }]);
    setChatInput('');

    // Simulated AI response
    setTimeout(() => {
      const responses: Record<string, string> = {
        default: `Analyzing "${userMsg}"... Based on the current incident context, I recommend checking the lateral movement indicators and cross-referencing with the MITRE ATT&CK T1021 technique mapping in the threat graph.`,
      };
      setChatMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: userMsg.toLowerCase().includes('ransom')
            ? 'The ransomware incident INC-2024-0047 is active. The SOAR engine has isolated fin-srv-03, blocked C2 IP 185.220.101.34, and initiated forensic capture. The hash matches BlackCat/ALPHV. Recommend: check for persistence mechanisms (T1547) and validate backup integrity.'
            : userMsg.toLowerCase().includes('status')
            ? `There are ${ACTIVE_INCIDENTS.length} active incidents. 1 critical (ransomware), 1 high (lateral movement). The swarm defense has deployed 12 hunter agents to the engineering subnet.`
            : responses.default,
        },
      ]);
    }, 800);
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-12 gap-3 sm:gap-4">
        {/* Playbook Library */}
        <div className="col-span-12 lg:col-span-4 card">
          <div className="card-header">Playbook Library</div>
          <div className="space-y-2">
            {PLAYBOOKS.map((pb) => (
              <div
                key={pb.name}
                className="flex flex-wrap items-start sm:items-center justify-between gap-2 p-3 bg-[#F5F8FF] border border-[#E2E9FA] rounded-lg hover:bg-[#EEF4FF] transition-colors"
              >
                <div className="min-w-0">
                  <div className="text-sm font-medium text-slate-800 truncate">
                    {pb.name.replace(/_/g, ' ')}
                  </div>
                  <div className="text-xs text-slate-500 mt-0.5 truncate">
                    {pb.steps} steps · {pb.trigger}
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className={`badge ${SEVERITY_STYLES[pb.severity]}`}>
                    {pb.severity}
                  </span>
                  <button className="px-2 py-1 bg-[#517EF9]/14 text-[#517EF9] rounded text-xs hover:bg-[#517EF9]/22 transition-colors">
                    Run
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Active Incidents */}
        <div className="col-span-12 lg:col-span-8 space-y-4">
          {/* Incident Selector */}
          <div className="card">
            <div className="card-header">Active Incidents</div>
            <div className="space-y-2">
              {ACTIVE_INCIDENTS.map((inc) => {
                const statusStyle = STATUS_STYLES[inc.status];
                return (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className={`flex flex-wrap sm:flex-nowrap items-start sm:items-center justify-between gap-2 p-3 rounded-lg cursor-pointer transition-colors ${
                      selectedIncident.id === inc.id
                        ? 'bg-[#517EF9]/10 border border-[#517EF9]/30'
                        : 'bg-[#F5F8FF] border border-[#E2E9FA] hover:bg-[#EEF4FF]'
                    }`}
                  >
                    <div className="flex items-start sm:items-center gap-3 min-w-0">
                      <span className={`badge ${SEVERITY_STYLES[inc.severity]} flex-shrink-0`}>
                        {inc.severity}
                      </span>
                      <div className="min-w-0">
                        <div className="text-sm font-medium break-words">{inc.title}</div>
                        <div className="text-xs text-slate-500 mt-0.5">
                          {inc.id} · {inc.playbook} · {new Date(inc.started_at).toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium flex-shrink-0 ${statusStyle.bg} ${statusStyle.text}`}
                    >
                      {inc.status}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Incident Timeline */}
          <div className="card">
            <div className="card-header">
              Incident Timeline — {selectedIncident.id}
            </div>
            <div className="relative ml-4 border-l-2 border-[#517EF9]/30 space-y-4 py-2">
              {selectedIncident.events.map((event, i) => (
                <div key={i} className="relative pl-6">
                  <div className="absolute -left-[9px] top-1 w-4 h-4 rounded-full bg-[#517EF9] border-2 border-white" />
                  <div className="flex items-center gap-2 text-xs text-slate-500">
                    <span className="font-mono">{event.timestamp}</span>
                    <span>·</span>
                    <span className="text-[#517EF9]">{event.actor}</span>
                  </div>
                  <div className="text-sm font-medium text-slate-800 mt-0.5">
                    {event.action}
                  </div>
                  <div className="text-sm text-slate-600 mt-0.5">
                    {event.detail}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Incident Chat / Copilot */}
        <div className="col-span-12 card">
          <div className="card-header">Incident Copilot</div>
          <div className="h-48 overflow-y-auto space-y-3 mb-3 p-3 bg-[#F5F8FF] border border-[#E2E9FA] rounded-lg">
            {chatMessages.map((msg, i) => (
              <div
                key={i}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[75%] px-3 py-2 rounded-lg text-sm ${
                    msg.role === 'user'
                      ? 'bg-[#517EF9] text-white'
                      : msg.role === 'assistant'
                      ? 'bg-white text-slate-700 border border-[#D8E3F7]'
                      : 'bg-[#EEF4FF] text-slate-500 italic'
                  }`}
                >
                  {msg.text}
                </div>
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendChat()}
              placeholder="Ask about incidents, playbooks, or recommended actions..."
              className="flex-1 bg-white border border-[#D8E3F7] rounded-lg px-4 py-2 text-sm outline-none focus:border-[#517EF9] text-slate-800 placeholder-slate-400"
            />
            <button
              onClick={handleSendChat}
              className="px-4 py-2 bg-[#517EF9] text-white rounded-lg text-sm font-medium hover:bg-[#436FE8] transition-colors"
            >
              Send
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
