import React, { useEffect, useMemo, useState } from 'react';

// ── Types ──────────────────────────────────────

interface Innovation {
  id: string;
  name: string;
  description: string;
  status: 'active' | 'degraded' | 'offline';
  metrics: { label: string; value: string }[];
  prompt: string;
}

type InnovationStatusResponse = {
  name: string;
  prompt: string;
  status: 'active' | 'degraded' | 'offline';
};

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080/api/v1';

// ── Mock Data ──────────────────────────────────

const INNOVATIONS: Innovation[] = [
  {
    id: 'swarm',
    name: 'Autonomous Swarm Defense',
    description: 'Multi-agent swarm intelligence with Byzantine-fault-tolerant consensus for distributed threat response.',
    status: 'active',
    metrics: [
      { label: 'Active Agents', value: '128' },
      { label: 'Consensus Latency', value: '45ms' },
      { label: 'Detections/min', value: '342' },
      { label: 'BFT Quorum', value: '87/128' },
    ],
    prompt: 'P12',
  },
  {
    id: 'dream',
    name: 'Dream-State Hunting',
    description: 'Off-peak deep analysis engine that retroactively scans historical events and amplifies weak signals.',
    status: 'active',
    metrics: [
      { label: 'Findings Today', value: '23' },
      { label: 'Weak Signals', value: '156' },
      { label: 'Retroactive Hits', value: '8' },
      { label: 'Avg Process Time', value: '3.2s' },
    ],
    prompt: 'P13',
  },
  {
    id: 'bio',
    name: 'Bio-Cyber Fusion Auth',
    description: 'ECG biometric + keystroke dynamics with Siamese network fusion for continuous operator authentication.',
    status: 'active',
    metrics: [
      { label: 'Enrolled Operators', value: '47' },
      { label: 'Auth Confidence', value: '99.2%' },
      { label: 'Fusion Score', value: '0.94' },
      { label: 'False Reject Rate', value: '0.3%' },
    ],
    prompt: 'P10',
  },
  {
    id: 'ephemeral',
    name: 'Ephemeral Infrastructure',
    description: 'Self-rotating pods, network segments, and secrets with integrity attestation and canary deployments.',
    status: 'active',
    metrics: [
      { label: 'Pod Rotations/h', value: '6' },
      { label: 'Secret Rotations/h', value: '2' },
      { label: 'Canary Tokens', value: '34' },
      { label: 'Integrity Score', value: '100%' },
    ],
    prompt: 'P11',
  },
  {
    id: 'cognitive',
    name: 'Cognitive Firewall',
    description: 'HMM-based attacker Theory of Mind predicting adversary intent along the kill chain.',
    status: 'active',
    metrics: [
      { label: 'Tracked IPs', value: '1,247' },
      { label: 'Blocked', value: '89' },
      { label: 'Honeypot Redirects', value: '23' },
      { label: 'Prediction Accuracy', value: '91.3%' },
    ],
    prompt: 'P12',
  },
  {
    id: 'selfheal',
    name: 'Self-Healing Code DNA',
    description: 'Rust genome registry with SHA-256 artifact hashing and automatic mutation healing.',
    status: 'degraded',
    metrics: [
      { label: 'Registered Genomes', value: '9' },
      { label: 'Mutations Detected', value: '2' },
      { label: 'Auto-Healed', value: '1' },
      { label: 'Integrity', value: '97.8%' },
    ],
    prompt: 'P14',
  },
  {
    id: 'satellite',
    name: 'Satellite Integrity Chain',
    description: 'GPS-timestamped tamper-evident integrity chain with satellite-grade time synchronization.',
    status: 'active',
    metrics: [
      { label: 'Chain Length', value: '48,291' },
      { label: 'Verified Entries', value: '48,291' },
      { label: 'GPS Satellites', value: '12' },
      { label: 'Time Accuracy', value: '±50ns' },
    ],
    prompt: 'P15',
  },
  {
    id: 'pqc',
    name: 'Post-Quantum Crypto',
    description: 'CRYSTALS-Kyber-1024 key encapsulation + Dilithium3 signatures for quantum-resistant zero trust.',
    status: 'active',
    metrics: [
      { label: 'Key Exchanges/s', value: '1,200' },
      { label: 'Signatures/s', value: '890' },
      { label: 'Active Sessions', value: '342' },
      { label: 'Algorithm', value: 'Kyber-1024' },
    ],
    prompt: 'P06',
  },
];

const STATUS_STYLES: Record<string, { bg: string; text: string; dot: string }> = {
  active: { bg: 'bg-green-500/10', text: 'text-green-400', dot: 'bg-green-500' },
  degraded: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  offline: { bg: 'bg-red-500/10', text: 'text-red-400', dot: 'bg-red-500' },
};

// ── Component ──────────────────────────────────

export default function Innovations() {
  const [items, setItems] = useState<Innovation[]>(INNOVATIONS);

  useEffect(() => {
    let cancelled = false;

    const fetchInnovationStatus = async () => {
      try {
        const res = await fetch(`${API_BASE}/innovations/status`);
        if (!res.ok) return;
        const data: InnovationStatusResponse[] = await res.json();
        if (cancelled) return;

        const statusByName = new Map(data.map((entry) => [entry.name, entry.status]));
        setItems(
          INNOVATIONS.map((innovation) => ({
            ...innovation,
            status: statusByName.get(innovation.name) ?? innovation.status,
          })),
        );
      } catch {
        // Keep static defaults when gateway status endpoint is unavailable.
      }
    };

    fetchInnovationStatus();
    const interval = setInterval(fetchInnovationStatus, 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const activeCount = items.filter((i) => i.status === 'active').length;
  const degradedCount = items.filter((i) => i.status === 'degraded').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold">8 Breakthrough Innovations</h1>
          <p className="text-slate-500 text-sm mt-1">
            Real-time status of Parirakṣakaḥ&apos;s unique defense capabilities
          </p>
        </div>
        <div className="flex gap-3 flex-shrink-0">
          <span className="badge badge-low">{activeCount} Active</span>
          {degradedCount > 0 && (
            <span className="badge badge-medium">{degradedCount} Degraded</span>
          )}
        </div>
      </div>

      {/* Innovation Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {items.map((innovation) => {
          const style = STATUS_STYLES[innovation.status];
          return (
            <div
              key={innovation.id}
              className="card hover:border-[#517EF9]/40 transition-colors group"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-[#517EF9]/15 flex items-center justify-center flex-shrink-0">
                    <span className="text-xs font-bold text-[#517EF9]">{innovation.prompt}</span>
                  </div>
                  <div>
                    <h3 className="font-semibold text-slate-800 group-hover:text-[#517EF9] transition-colors">
                      {innovation.name}
                    </h3>
                    <span className="text-xs text-slate-500">{innovation.prompt}</span>
                  </div>
                </div>
                <span
                  className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium ${style.bg} ${style.text}`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${style.dot} animate-pulse`} />
                  {innovation.status}
                </span>
              </div>

              <p className="text-sm text-slate-600 mb-4">{innovation.description}</p>

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 gap-2">
                {innovation.metrics.map((m) => (
                  <div
                    key={m.label}
                    className="bg-[#F2F6FF] rounded-lg px-3 py-2 border border-[#DFE8FA]"
                  >
                    <div className="text-lg font-bold text-[#517EF9]">{m.value}</div>
                    <div className="text-xs text-slate-500">{m.label}</div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
