import React, { useState, useMemo, useCallback } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

// ── Types ──────────────────────────────────────

interface ThreatNode {
  id: string;
  label: string;
  type: 'ip' | 'domain' | 'hash' | 'technique' | 'campaign';
  severity: number;
}

interface ThreatEdge {
  source: string;
  target: string;
  relation: string;
}

// ── Mock Data ──────────────────────────────────

function generateMockGraph(): { nodes: ThreatNode[]; edges: ThreatEdge[] } {
  const nodes: ThreatNode[] = [
    { id: 'c1', label: 'Operation DarkStorm', type: 'campaign', severity: 0.95 },
    { id: 't1', label: 'T1071 - App Layer', type: 'technique', severity: 0.8 },
    { id: 't2', label: 'T1021 - Remote Svc', type: 'technique', severity: 0.7 },
    { id: 't3', label: 'T1486 - Ransomware', type: 'technique', severity: 0.95 },
    { id: 'ip1', label: '45.33.32.156', type: 'ip', severity: 0.9 },
    { id: 'ip2', label: '185.220.101.34', type: 'ip', severity: 0.85 },
    { id: 'ip3', label: '10.0.5.42', type: 'ip', severity: 0.6 },
    { id: 'd1', label: 'evil-c2.example.com', type: 'domain', severity: 0.88 },
    { id: 'd2', label: 'phish-login.net', type: 'domain', severity: 0.75 },
    { id: 'h1', label: 'a1b2c3...deadbeef', type: 'hash', severity: 0.92 },
  ];
  const edges: ThreatEdge[] = [
    { source: 'c1', target: 't1', relation: 'uses' },
    { source: 'c1', target: 't2', relation: 'uses' },
    { source: 'c1', target: 't3', relation: 'uses' },
    { source: 't1', target: 'ip1', relation: 'observed_from' },
    { source: 't1', target: 'd1', relation: 'resolves_to' },
    { source: 't2', target: 'ip2', relation: 'observed_from' },
    { source: 't3', target: 'h1', relation: 'indicator' },
    { source: 'ip1', target: 'd1', relation: 'resolves' },
    { source: 'ip2', target: 'ip3', relation: 'lateral_movement' },
    { source: 'd2', target: 'ip1', relation: 'redirects_to' },
  ];
  return { nodes, edges };
}

function generateTimeline() {
  const now = Date.now();
  return Array.from({ length: 48 }, (_, i) => ({
    time: new Date(now - (47 - i) * 1800_000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    }),
    threats: Math.floor(Math.random() * 15) + 1,
    anomalies: Math.floor(Math.random() * 8),
  }));
}

// ── Node Colors ────────────────────────────────

const NODE_COLORS: Record<string, string> = {
  campaign: '#EF4444',
  technique: '#F59E0B',
  ip: '#517EF9',
  domain: '#10B981',
  hash: '#EC4899',
};

// ── Component ──────────────────────────────────

export default function ThreatHunting() {
  const [searchQuery, setSearchQuery] = useState('');
  const graph = useMemo(() => generateMockGraph(), []);
  const [selectedNode, setSelectedNode] = useState<ThreatNode | null>(() => generateMockGraph().nodes[0]);
  const timeline = useMemo(() => generateTimeline(), []);

  const filteredNodes = useMemo(() => {
    if (!searchQuery) return graph.nodes;
    const q = searchQuery.toLowerCase();
    return graph.nodes.filter(
      (n) => n.label.toLowerCase().includes(q) || n.type.includes(q),
    );
  }, [searchQuery, graph.nodes]);

  return (
    <div className="space-y-6">
      {/* Search Bar */}
      <div className="card">
        <div className="flex items-center gap-4">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" className="text-slate-400 flex-shrink-0">
            <circle cx="11" cy="11" r="8" stroke="currentColor" strokeWidth="1.8"/>
            <path d="m21 21-4.35-4.35" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
          </svg>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search IPs, domains, hashes, MITRE techniques, campaigns..."
            className="flex-1 bg-transparent border-none outline-none text-slate-800 placeholder-slate-400 text-sm"
          />
          <button className="px-4 py-2 bg-[#517EF9] text-white rounded-lg text-sm font-medium hover:bg-[#436FE8] transition-colors">
            Hunt
          </button>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-3 sm:gap-4">
        {/* Attack Graph (D3-style with SVG) */}
        <div className="col-span-12 lg:col-span-8 card">
          <div className="card-header">Attack Graph</div>
          <svg width="100%" height="400" viewBox="0 0 800 400" className="rounded-lg">
            <defs>
              <marker
                id="arrowhead"
                viewBox="0 0 10 10"
                refX="25"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#A1B4D8" />
              </marker>
            </defs>

            {/* Edges */}
            {graph.edges.map((e, i) => {
              const src = graph.nodes.find((n) => n.id === e.source);
              const tgt = graph.nodes.find((n) => n.id === e.target);
              if (!src || !tgt) return null;
              const si = graph.nodes.indexOf(src);
              const ti = graph.nodes.indexOf(tgt);
              const sx = 100 + (si % 5) * 150;
              const sy = 80 + Math.floor(si / 5) * 160;
              const tx = 100 + (ti % 5) * 150;
              const ty = 80 + Math.floor(ti / 5) * 160;
              return (
                <g key={i}>
                  <line
                    x1={sx}
                    y1={sy}
                    x2={tx}
                    y2={ty}
                    stroke="#B8C7E6"
                    strokeWidth={1.5}
                    markerEnd="url(#arrowhead)"
                  />
                  <text
                    x={(sx + tx) / 2}
                    y={(sy + ty) / 2 - 6}
                    fill="#64748B"
                    fontSize="9"
                    textAnchor="middle"
                  >
                    {e.relation}
                  </text>
                </g>
              );
            })}

            {/* Nodes */}
            {graph.nodes.map((node, i) => {
              const cx = 100 + (i % 5) * 150;
              const cy = 80 + Math.floor(i / 5) * 160;
              const isFiltered = filteredNodes.includes(node);
              const isSelected = selectedNode?.id === node.id;
              return (
                <g
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className="cursor-pointer"
                  opacity={searchQuery && !isFiltered ? 0.2 : 1}
                >
                  <circle
                    cx={cx}
                    cy={cy}
                    r={isSelected ? 22 : 18}
                    fill={NODE_COLORS[node.type] || '#517EF9'}
                    opacity={0.8}
                    stroke={isSelected ? '#fff' : 'transparent'}
                    strokeWidth={2}
                  />
                  <text
                    x={cx}
                    y={cy + 32}
                    fill="#475569"
                    fontSize="10"
                    textAnchor="middle"
                  >
                    {node.label.length > 18
                      ? node.label.slice(0, 16) + '...'
                      : node.label}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Legend */}
          <div className="flex flex-wrap gap-3 mt-3 text-xs text-slate-500">
            {Object.entries(NODE_COLORS).map(([type, color]) => (
              <span key={type} className="flex items-center gap-1">
                <span className="w-3 h-3 rounded-full" style={{ background: color }} />
                {type}
              </span>
            ))}
          </div>
        </div>

        {/* Node Detail Panel */}
        <div className="col-span-12 lg:col-span-4 card">
          <div className="card-header">Node Details</div>
          {selectedNode ? (
            <div className="space-y-3">
              <div>
                <span
                  className="inline-block px-2 py-1 rounded text-xs font-bold"
                  style={{
                    background: NODE_COLORS[selectedNode.type] + '33',
                    color: NODE_COLORS[selectedNode.type],
                  }}
                >
                  {selectedNode.type.toUpperCase()}
                </span>
              </div>
              <h3 className="text-lg font-semibold break-all text-slate-800">{selectedNode.label}</h3>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500">Severity:</span>
                <div className="flex-1 h-2 bg-slate-200 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${selectedNode.severity * 100}%`,
                      background:
                        selectedNode.severity > 0.8
                          ? '#EF4444'
                          : selectedNode.severity > 0.5
                          ? '#F59E0B'
                          : '#10B981',
                    }}
                  />
                </div>
                <span className="text-xs font-mono">
                  {(selectedNode.severity * 100).toFixed(0)}%
                </span>
              </div>
              <div className="text-sm text-slate-600 mt-4">
                <p className="font-medium text-slate-700 mb-2">Connected Entities:</p>
                {graph.edges
                  .filter(
                    (e) =>
                      e.source === selectedNode.id || e.target === selectedNode.id,
                  )
                  .map((e, i) => {
                    const otherId =
                      e.source === selectedNode.id ? e.target : e.source;
                    const other = graph.nodes.find((n) => n.id === otherId);
                    return (
                      <div
                        key={i}
                        className="flex items-center gap-2 py-1 border-b border-slate-200"
                      >
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{
                            background: NODE_COLORS[other?.type || 'ip'],
                          }}
                        />
                        <span className="text-xs">{other?.label}</span>
                        <span className="text-xs text-slate-500 ml-auto">
                          {e.relation}
                        </span>
                      </div>
                    );
                  })}
              </div>
            </div>
          ) : (
            <p className="text-slate-500 text-sm">Click a node to view details</p>
          )}
        </div>

        {/* Threat Timeline */}
        <div className="col-span-12 card">
          <div className="card-header">Threat Activity Timeline (24h)</div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="#D8E3F7" />
              <XAxis dataKey="time" tick={{ fill: '#64748B', fontSize: 10 }} />
              <YAxis tick={{ fill: '#64748B', fontSize: 11 }} />
              <Tooltip
                contentStyle={{
                  background: '#FFFFFF',
                  border: '1px solid #D8E3F7',
                  borderRadius: 8,
                }}
              />
              <Line
                type="monotone"
                dataKey="threats"
                stroke="#EF4444"
                strokeWidth={2}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="anomalies"
                stroke="#F59E0B"
                strokeWidth={1.5}
                strokeDasharray="4 4"
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
