import React from 'react';
import type { Alert } from '../store/useAppStore';

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
};

interface AlertFeedProps {
  alerts: Alert[];
}

export default function AlertFeed({ alerts }: AlertFeedProps) {
  if (alerts.length === 0) {
    return <p className="text-slate-500 text-sm">No alerts</p>;
  }

  return (
    <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
      {alerts.map((alert) => (
        <div
          key={alert.id}
          className="flex items-start gap-3 p-2.5 bg-[#F5F8FF] border border-[#E2E9FA] rounded-lg hover:bg-[#EDF3FF] transition-colors"
        >
          <div className="mt-0.5">
            <span className={`badge ${SEVERITY_BADGE[alert.severity]}`}>
              {alert.severity}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-slate-800 truncate">
                {alert.type}
              </span>
              {alert.mitre_technique && (
                <span className="text-xs text-[#517EF9] bg-[#517EF9]/12 px-1.5 py-0.5 rounded">
                  {alert.mitre_technique}
                </span>
              )}
              {alert.kill_chain_stage && (
                <span className="text-xs text-cyan-700 bg-cyan-500/10 px-1.5 py-0.5 rounded">
                  {alert.kill_chain_stage}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 truncate mt-0.5">
              {alert.description}
            </p>
            <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
              <span className="font-mono">{alert.source_ip}</span>
              {alert.campaign_id && (
                <span className="text-cyan-400/80">{alert.campaign_id.slice(0, 8)}</span>
              )}
              {typeof alert.campaign_risk_score === 'number' && (
                <span>risk {Math.round(alert.campaign_risk_score * 100)}%</span>
              )}
              <span>
                {new Date(alert.timestamp).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                })}
              </span>
            </div>
          </div>
          <div>
            <span
              className={`w-2 h-2 rounded-full inline-block ${
                alert.status === 'open'
                  ? 'bg-red-500'
                  : alert.status === 'investigating'
                  ? 'bg-yellow-500'
                  : 'bg-green-500'
              }`}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
