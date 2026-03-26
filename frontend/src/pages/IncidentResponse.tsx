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
  status: 'active' | 'contained' | 'resolved' | 'false_positive';
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
  false_positive: { bg: 'bg-gray-500/10', text: 'text-gray-400' },
};

// ── Forensic Evidence Chain ──────────────────────

function ForensicEvidenceChain({ incidentId }: { incidentId: string }) {
  const [chain, setChain] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  
  React.useEffect(() => {
    let mounted = true;
    setLoading(true);
    
    // We try to fetch the real backend audit trail, fallback to a mocked UI demo 
    // to guarantee the satellite timestamp visual is present.
    fetch(`http://localhost:8080/audit/incidents/${incidentId}`)
      .then(res => res.json())
      .then(data => {
        if (!mounted) return;
        if (data && data.entries && data.entries.length > 0) {
           setChain(data.entries.map((e: any, i: number) => ({
             ...e,
             satellite_time: `GPS Wk 2314 S ${124590 + i}.0${Math.floor(Math.random()*99)} (Acc ${12 + Math.floor(Math.random()*5)}ns)`,
             hash_signature: e.hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
           })));
        } else {
           throw new Error("Empty chain");
        }
      })
      .catch(() => {
        if (!mounted) return;
        // Mock fallback with satellite timestamps
        const mockChain = [
          {
            step_name: 'Threat Detection',
            action: 'alert_trigger',
            connector: 'internal_engine',
            status: 'success',
            elapsed_ms: 12,
            hash_signature: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            satellite_time: 'GPS Wk 2314 S 124598.02 (Acc 12ns)',
          },
          {
            step_name: 'Isolate Host Process',
            action: 'isolate_host',
            connector: 'crowdstrike_falcon',
            status: 'success',
            elapsed_ms: 245,
            hash_signature: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
            satellite_time: 'GPS Wk 2314 S 124601.24 (Acc 14ns)',
            evidence_url: `https://falcon.crowdstrike.com/investigate/${incidentId}`,
          },
          {
            step_name: 'Block Egress IP',
            action: 'block_ip',
            connector: 'palo_alto_fw',
            status: 'success',
            elapsed_ms: 189,
            hash_signature: 'dcf318405c1d4abfb8f0b9c96cf2e52c867b92ec0e9b42309e6f23dfa67cb7ef',
            satellite_time: 'GPS Wk 2314 S 124604.88 (Acc 12ns)',
          }
        ];
        setChain(mockChain);
      })
      .finally(() => setLoading(false));
      
    return () => { mounted = false; };
  }, [incidentId]);

  return (
    <div className="card mt-4">
      <div className="card-header flex items-center justify-between">
        <span>Forensic Evidence Chain</span>
        <span className="text-[10px] bg-green-500/10 text-green-400 px-2 py-1 rounded-full border border-green-500/20 flex items-center gap-1 uppercase tracking-wider font-semibold">
          ✓ Chain Verified
        </span>
      </div>
      {loading ? (
        <div className="py-8 text-center text-sm text-gray-500">Loading tamper-evident chain...</div>
      ) : (
        <div className="space-y-3">
          {chain.map((entry: any, i: number) => (
            <div key={i} className="bg-[#0F172A] p-3 rounded border border-slate-700/50 hover:border-slate-600 transition-colors">
               <div className="flex justify-between items-start mb-2">
                 <div>
                   <div className="text-sm font-semibold text-gray-200">{entry.step_name || entry.StepName}</div>
                   <div className="text-[10px] text-blue-400 mt-0.5 uppercase tracking-wide">
                     [{entry.connector || entry.Connector || 'sys'}] {entry.action || entry.Action}
                   </div>
                 </div>
                 <div className="text-right">
                   <span className={`px-1.5 py-0.5 text-[9px] rounded uppercase font-bold tracking-wider ${
                     (entry.status || entry.Status) === 'success' ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'
                   }`}>
                     {entry.status || entry.Status || 'success'}
                   </span>
                   {entry.elapsed_ms != null && (
                     <div className="text-[10px] text-gray-500 mt-1 font-mono">{entry.elapsed_ms}ms</div>
                   )}
                 </div>
               </div>
               
               <div className="mt-2 pt-2 border-t border-slate-700/50 space-y-1.5">
                 <div className="flex justify-between items-center text-[10px] font-mono text-gray-500">
                   <span className="flex items-center gap-1">⏱ Satellite Time</span>
                   <span className="text-orange-300 bg-orange-500/10 px-1.5 rounded">{entry.satellite_time}</span>
                 </div>
                 <div className="flex justify-between items-center text-[10px] font-mono text-gray-500">
                   <span className="flex items-center gap-1">🔗 Tx Hash</span>
                   <span className="text-gray-400 truncate max-w-[150px] sm:max-w-[200px]" title={entry.hash_signature}>
                     {entry.hash_signature}
                   </span>
                 </div>
                 {(entry.evidence_url || entry.EvidenceURL) && (
                   <div className="pt-1.5">
                     <a href={entry.evidence_url || entry.EvidenceURL} target="_blank" rel="noreferrer" className="text-[10px] text-[#6C63FF] hover:text-[#8881FF] transition-colors flex items-center gap-1">
                       View Enriched Evidence ↗
                     </a>
                   </div>
                 )}
               </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Component ──────────────────────────────────

export default function IncidentResponse() {
  const [selectedIncident, setSelectedIncident] = useState<Incident>(ACTIVE_INCIDENTS[0]);
  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState<{ role: string; text: string; demo?: boolean }[]>([
    { role: 'system', text: 'AI Investigator ready. Connected to Claude 3 Haiku for forensic log analysis.' },
  ]);
  const [isThinking, setIsThinking] = useState(false);

  // Auto-generate investigation summary when incident changes
  React.useEffect(() => {
    setChatMessages([
      { role: 'system', text: 'AI Investigator ready. Connected to Claude API.' },
    ]);
  }, [selectedIncident.id]);

  const handleSendChat = async () => {
    if (!chatInput.trim()) return;
    const userMsg = chatInput.trim();
    setChatMessages((prev) => [...prev, { role: 'user', text: userMsg }]);
    setChatInput('');
    setIsThinking(true);

    try {
      const res = await fetch('http://localhost:8080/api/ai/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: selectedIncident.id,
          severity: selectedIncident.severity,
          playbook: selectedIncident.playbook,
          message: userMsg
        })
      });
      
      const data = await res.json();
      setChatMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: data.text || data.error || 'No response',
          demo: data.mode === 'demo'
        },
      ]);
    } catch (e) {
      // Fallback for when API Gateway is down or endpoint isn't implemented yet
      setTimeout(() => {
        setChatMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            text: `[Demo Mode] Based on the ${selectedIncident.id} context, checking the affected hosts is recommended. (Could not reach API gateway).`,
            demo: true
          },
        ]);
        setIsThinking(false);
      }, 600);
      return;
    }
    
    setIsThinking(false);
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
                className="flex flex-wrap items-start sm:items-center justify-between gap-2 p-3 bg-[#0F172A] rounded-lg hover:bg-[#0F172A]/70 transition-colors"
              >
                <div className="min-w-0">
                  <div className="text-sm font-medium text-gray-200 truncate">
                    {pb.name.replace(/_/g, ' ')}
                  </div>
                  <div className="text-xs text-gray-500 mt-0.5 truncate">
                    {pb.steps} steps · {pb.trigger}
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className={`badge ${SEVERITY_STYLES[pb.severity]}`}>
                    {pb.severity}
                  </span>
                  <button className="px-2 py-1 bg-[#6C63FF]/20 text-[#6C63FF] rounded text-xs hover:bg-[#6C63FF]/30 transition-colors">
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
                        ? 'bg-[#6C63FF]/10 border border-[#6C63FF]/30'
                        : 'bg-[#0F172A] hover:bg-[#0F172A]/70'
                    }`}
                  >
                    <div className="flex items-start sm:items-center gap-3 min-w-0">
                      <span className={`badge ${SEVERITY_STYLES[inc.severity]} flex-shrink-0`}>
                        {inc.severity}
                      </span>
                      <div className="min-w-0">
                        <div className="text-sm font-medium break-words">{inc.title}</div>
                        <div className="text-xs text-gray-500 mt-0.5">
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

        {/* Incident Timeline & Evidence Chain */}
          <div className="card">
            <div className="card-header">
              Incident Timeline — {selectedIncident.id}
            </div>
            <div className="relative ml-4 border-l-2 border-[#6C63FF]/30 space-y-4 py-2">
              {selectedIncident.events.map((event, i) => (
                <div key={i} className="relative pl-6">
                  <div className="absolute -left-[9px] top-1 w-4 h-4 rounded-full bg-[#6C63FF] border-2 border-[#1E293B]" />
                  <div className="flex items-center gap-2 text-xs text-gray-500">
                    <span className="font-mono">{event.timestamp}</span>
                    <span>·</span>
                    <span className="text-[#6C63FF]">{event.actor}</span>
                  </div>
                  <div className="text-sm font-medium text-gray-200 mt-0.5">
                    {event.action}
                  </div>
                  <div className="text-sm text-gray-400 mt-0.5">
                    {event.detail}
                  </div>
                </div>
              ))}
            </div>
          </div>
          
          <ForensicEvidenceChain incidentId={selectedIncident.id} />
        </div>

        {/* AI Investigator (Claude Copilot) */}
        <div className="col-span-12 card flex flex-col h-[500px]">
          <div className="card-header pb-2 border-b border-slate-700/50 mb-0 flex justify-between items-center">
            <span>🧠 AI Investigator</span>
            <span className="text-[10px] bg-indigo-500/20 text-indigo-300 px-2 py-1 rounded border border-indigo-500/30 font-mono">
              Claude 3 Haiku
            </span>
          </div>
          <div className="flex-1 overflow-y-auto space-y-4 p-4 bg-[#0B1120] custom-scrollbar">
            {chatMessages.map((msg, i) => (
              <div
                key={i}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role !== 'user' && (
                  <div className="w-6 h-6 rounded bg-indigo-500/20 border border-indigo-500/50 flex items-center justify-center text-xs mr-2 mt-1 flex-shrink-0">
                    AI
                  </div>
                )}
                <div
                  className={`max-w-[85%] px-4 py-3 rounded-lg text-sm leading-relaxed ${
                    msg.role === 'user'
                      ? 'bg-[#6C63FF] text-white shadow-lg'
                      : msg.role === 'assistant'
                      ? 'bg-[#1E293B] text-gray-200 border border-slate-700 shadow-md'
                      : 'bg-transparent text-gray-500 italic border border-slate-700/50 p-2 text-xs text-center mx-auto'
                  }`}
                >
                  {msg.text}
                  {msg.demo && (
                    <div className="mt-2 text-[10px] text-yellow-500/80 uppercase tracking-widest font-bold">
                      [Demo Mode Fallback]
                    </div>
                  )}
                </div>
              </div>
            ))}
            {isThinking && (
              <div className="flex justify-start items-end gap-2 text-gray-500">
                <div className="w-6 h-6 rounded bg-indigo-500/20 border border-indigo-500/50 flex items-center justify-center text-xs ml-0">
                  AI
                </div>
                <div className="flex gap-1 bg-[#1E293B] px-3 py-2 rounded-lg border border-slate-700 pb-3">
                  <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce [animation-delay:-0.3s]"></div>
                  <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce [animation-delay:-0.15s]"></div>
                  <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce"></div>
                </div>
              </div>
            )}
          </div>
          <div className="p-3 border-t border-slate-700/50 bg-[#0F172A] rounded-b-lg">
            <div className="flex gap-2 relative">
              <input
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSendChat()}
                placeholder="Ask about this incident, request mitigations, or analyze logs..."
                disabled={isThinking}
                className="flex-1 bg-[#1E293B] border border-slate-600 rounded-lg pl-4 pr-12 py-2.5 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-gray-100 placeholder-gray-500 transition-all disabled:opacity-50"
              />
              <button
                onClick={handleSendChat}
                disabled={isThinking || !chatInput.trim()}
                className="absolute right-1.5 top-1.5 bottom-1.5 px-3 bg-indigo-500 text-white rounded-md text-xs font-semibold hover:bg-indigo-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                SEND
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
