/**
 * CipherChart — Recharts cipher breakdown pie/donut chart.
 */
import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const STATUS_COLORS = {
  'Quantum Safe': '#00E676',
  'Hybrid Ready': '#FFD600',
  'Vulnerable': '#FF1744',
};

const ALGO_COLORS = [
  '#00E5FF', '#00E676', '#FFD600', '#FF1744',
  '#7C4DFF', '#FF6D00', '#00BFA5', '#D500F9',
  '#2979FF', '#FF4081',
];

export default function CipherChart({ assets = [], type = 'status' }) {
  if (!assets.length) {
    return (
      <div className="glass-card p-6 flex items-center justify-center h-64 text-gray-500">
        No data available
      </div>
    );
  }

  const data = type === 'status' ? getStatusData(assets) : getAlgorithmData(assets);

  return (
    <div className="glass-card p-6">
      <h3 className="section-title mb-4">
        <span>{type === 'status' ? '🛡️' : '🔐'}</span>
        {type === 'status' ? 'PQC Status Distribution' : 'Algorithm Breakdown'}
      </h3>
      <ResponsiveContainer width="100%" height={280}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
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
          <Tooltip
            contentStyle={{
              background: '#0D1B2A',
              border: '1px solid rgba(0, 229, 255, 0.2)',
              borderRadius: '8px',
              color: '#E0E0E0',
              fontSize: '12px',
            }}
          />
          <Legend
            verticalAlign="bottom"
            height={36}
            iconType="circle"
            formatter={(value) => <span className="text-gray-300 text-xs">{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

function getStatusData(assets) {
  const counts = { 'Quantum Safe': 0, 'Hybrid Ready': 0, 'Vulnerable': 0 };
  assets.forEach((a) => {
    if (a.pqc_status === 'QUANTUM_SAFE') counts['Quantum Safe']++;
    else if (a.pqc_status === 'HYBRID_READY') counts['Hybrid Ready']++;
    else counts['Vulnerable']++;
  });
  return Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));
}

function getAlgorithmData(assets) {
  const algoCounts = {};
  assets.forEach((a) => {
    const kex = a.key_exchange || a.tls_fingerprint?.key_exchange || 'Unknown';
    algoCounts[kex] = (algoCounts[kex] || 0) + 1;
  });
  return Object.entries(algoCounts).map(([name, value]) => ({ name, value }));
}
