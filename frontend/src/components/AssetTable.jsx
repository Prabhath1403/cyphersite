/**
 * AssetTable — Assets list with PQC status badges and risk scores.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import PQCBadge from './PQCBadge';

export default function AssetTable({ assets = [] }) {
  if (!assets.length) {
    return (
      <div className="glass-card p-8 text-center text-gray-500">
        <p className="text-lg">No assets discovered yet</p>
        <p className="text-sm mt-1">Assets will appear here after a scan completes</p>
      </div>
    );
  }

  return (
    <div className="glass-card overflow-hidden">
      <table className="w-full">
        <thead>
          <tr className="table-header">
            <th className="px-6 py-4 text-left">Asset</th>
            <th className="px-6 py-4 text-left">Service</th>
            <th className="px-6 py-4 text-left">Port</th>
            <th className="px-6 py-4 text-left">PQC Status</th>
            <th className="px-6 py-4 text-left">Risk Score</th>
            <th className="px-6 py-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => (
            <tr key={asset.id} className="table-row">
              <td className="px-6 py-4">
                <div>
                  <p className="font-medium text-gray-200">{asset.hostname}</p>
                  <p className="text-xs text-gray-500 font-mono">{asset.ip_address || '—'}</p>
                </div>
              </td>
              <td className="px-6 py-4">
                <span className="text-sm text-gray-400 capitalize">{asset.service_type?.replace('_', ' ')}</span>
              </td>
              <td className="px-6 py-4">
                <span className="font-mono text-sm text-gray-300">{asset.port}</span>
              </td>
              <td className="px-6 py-4">
                <PQCBadge status={asset.pqc_status} />
              </td>
              <td className="px-6 py-4">
                <RiskScore score={asset.risk_score} />
              </td>
              <td className="px-6 py-4 text-right">
                <Link
                  to={`/asset/${asset.id}`}
                  className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors font-medium"
                >
                  View Details →
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RiskScore({ score }) {
  if (score == null) return <span className="text-gray-500">—</span>;

  const color =
    score >= 80 ? 'text-red-400' :
    score >= 60 ? 'text-orange-400' :
    score >= 40 ? 'text-amber-400' :
    score >= 20 ? 'text-yellow-300' :
    'text-emerald-400';

  const bgColor =
    score >= 80 ? 'bg-red-400' :
    score >= 60 ? 'bg-orange-400' :
    score >= 40 ? 'bg-amber-400' :
    score >= 20 ? 'bg-yellow-300' :
    'bg-emerald-400';

  return (
    <div className="flex items-center gap-3">
      <div className="w-20 h-2 bg-navy-800 rounded-full overflow-hidden">
        <div className={`h-full ${bgColor} rounded-full transition-all`} style={{ width: `${score}%` }} />
      </div>
      <span className={`font-mono text-sm font-semibold ${color}`}>{score.toFixed(0)}</span>
    </div>
  );
}
