/**
 * CipherChart — Recharts cipher breakdown pie/donut chart with enterprise styling.
 */
import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { ShieldCheck, ShieldAlert, AlertTriangle, PieChart as PieIcon, Lock } from 'lucide-react';

const STATUS_COLORS = {
  'Quantum Safe': '#10B981',
  'Hybrid Ready': '#F59E0B',
  'Vulnerable': '#F43F5E',
};

const ALGO_COLORS = [
  '#00E5FF', '#10B981', '#F59E0B', '#F43F5E',
  '#6366F1', '#EC4899', '#14B8A6', '#8B5CF6',
  '#3B82F6', '#FB923C',
];

export default function CipherChart({ assets = [], summaryCounts = null, type = 'status' }) {
  let data = [];

  if (summaryCounts) {
    data = Object.entries(summaryCounts)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({ name, value }));
  } else if (assets.length > 0) {
    data = type === 'status' ? getStatusData(assets) : getAlgorithmData(assets);
  }

  const total = data.reduce((sum, item) => sum + item.value, 0);

  if (!data.length || total === 0) {
    return (
      <div className="glass-card p-6 flex flex-col items-center justify-center h-80 text-gray-500">
        <PieIcon className="w-8 h-8 text-gray-600 mb-2" />
        <p className="text-sm font-medium">No distribution data available</p>
        <p className="text-xs text-gray-600 mt-1">Run a scan to generate cryptography breakdowns</p>
      </div>
    );
  }

  return (
    <div className="glass-card p-6 flex flex-col justify-between h-full">
      <div>
        <div className="flex items-center justify-between mb-4">
          <h3 className="section-title">
            {type === 'status' ? (
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
            ) : (
              <Lock className="w-4 h-4 text-cyan-400" />
            )}
            <span>{type === 'status' ? 'PQC Readiness Breakdown' : 'Cryptographic Primitives'}</span>
          </h3>
          <span className="text-xs font-mono text-gray-400">
            {total.toLocaleString()} findings
          </span>
        </div>

        <div className="relative h-60 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={65}
                outerRadius={95}
                paddingAngle={3}
                dataKey="value"
                stroke="none"
              >
                {data.map((entry, i) => (
                  <Cell
                    key={`cell-${i}`}
                    fill={type === 'status' ? STATUS_COLORS[entry.name] || ALGO_COLORS[i] : ALGO_COLORS[i % ALGO_COLORS.length]}
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>

          {/* Center Metric */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-2xl font-extrabold text-white font-mono">
              {total.toLocaleString()}
            </span>
            <span className="text-[10px] text-gray-400 uppercase tracking-wider font-semibold">
              Total Assets
            </span>
          </div>
        </div>
      </div>

      {/* Legend / Metrics row */}
      <div className="grid grid-cols-3 gap-2 pt-4 border-t border-white/[0.06] text-center">
        {data.map((entry) => {
          const pct = Math.round((entry.value / total) * 100);
          const colorClass =
            entry.name === 'Quantum Safe' ? 'text-emerald-400' :
            entry.name === 'Hybrid Ready' ? 'text-amber-400' : 'text-rose-400';
          return (
            <div key={entry.name} className="px-2 py-1 rounded bg-white/[0.02]">
              <div className="text-[10px] text-gray-400 truncate">{entry.name}</div>
              <div className={`text-sm font-bold font-mono ${colorClass}`}>
                {pct}%
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function CustomTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div className="bg-navy-900/95 border border-white/10 rounded-lg px-3 py-2 shadow-xl backdrop-blur-md">
        <div className="text-xs font-semibold text-gray-200">{data.name}</div>
        <div className="text-sm font-bold font-mono text-cyan-400 mt-0.5">
          {data.value?.toLocaleString()} assets
        </div>
      </div>
    );
  }
  return null;
}

function getStatusData(assets) {
  const counts = { 'Quantum Safe': 0, 'Hybrid Ready': 0, 'Vulnerable': 0 };
  assets.forEach((a) => {
    const s = (a.pqc_status || '').toUpperCase();
    if (s.includes('SAFE')) counts['Quantum Safe']++;
    else if (s.includes('HYBRID') || s.includes('MARGIN') || s.includes('REDUCED')) counts['Hybrid Ready']++;
    else counts['Vulnerable']++;
  });
  return Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));
}

function getAlgorithmData(assets) {
  const algoCounts = {};
  assets.forEach((a) => {
    const kex = a.algorithm || a.key_exchange || a.tls_fingerprint?.key_exchange || 'Other';
    algoCounts[kex] = (algoCounts[kex] || 0) + 1;
  });
  return Object.entries(algoCounts).map(([name, value]) => ({ name, value }));
}
