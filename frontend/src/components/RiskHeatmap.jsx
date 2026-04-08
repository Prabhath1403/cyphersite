/**
 * RiskHeatmap — Grid-based risk heatmap visualization.
 */
import React from 'react';

function getRiskColor(score) {
  if (score >= 80) return 'bg-red-500/80 border-red-400/30';
  if (score >= 60) return 'bg-orange-500/70 border-orange-400/30';
  if (score >= 40) return 'bg-amber-500/60 border-amber-400/30';
  if (score >= 20) return 'bg-yellow-400/40 border-yellow-400/20';
  return 'bg-emerald-400/40 border-emerald-400/20';
}

function getRiskTextColor(score) {
  if (score >= 80) return 'text-red-300';
  if (score >= 60) return 'text-orange-300';
  if (score >= 40) return 'text-amber-300';
  if (score >= 20) return 'text-yellow-200';
  return 'text-emerald-300';
}

export default function RiskHeatmap({ assets = [] }) {
  if (!assets.length) {
    return (
      <div className="glass-card p-6 flex items-center justify-center h-48 text-gray-500">
        No risk data available
      </div>
    );
  }

  return (
    <div className="glass-card p-6">
      <h3 className="section-title mb-4">
        <span>🌡️</span> Risk Heatmap
      </h3>

      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3">
        {assets.slice(0, 20).map((asset) => (
          <div
            key={asset.id}
            className={`p-3 rounded-lg border transition-all duration-300 hover:scale-105 cursor-pointer ${getRiskColor(
              asset.risk_score || 0
            )}`}
            title={`${asset.hostname}: Risk ${asset.risk_score?.toFixed(0) || 0}`}
          >
            <p className="text-xs font-medium text-white/90 truncate">{asset.hostname}</p>
            <p className={`text-lg font-bold font-mono mt-1 ${getRiskTextColor(asset.risk_score || 0)}`}>
              {asset.risk_score?.toFixed(0) || '—'}
            </p>
            <p className="text-[10px] text-white/50 mt-0.5">:{asset.port}</p>
          </div>
        ))}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 mt-4 pt-4 border-t border-white/5">
        <span className="text-xs text-gray-500">Risk Level:</span>
        {[
          { label: 'Low', color: 'bg-emerald-400/40' },
          { label: 'Medium', color: 'bg-amber-500/60' },
          { label: 'High', color: 'bg-orange-500/70' },
          { label: 'Critical', color: 'bg-red-500/80' },
        ].map(({ label, color }) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className={`w-3 h-3 rounded ${color}`} />
            <span className="text-xs text-gray-400">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
