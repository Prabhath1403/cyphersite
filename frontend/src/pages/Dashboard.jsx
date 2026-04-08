/**
 * Dashboard — Main overview page with stats, recent scans, and charts.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import { useDashboardStats, useScans } from '../hooks/useScanResults';
import CipherChart from '../components/CipherChart';
import PQCBadge from '../components/PQCBadge';

const STAT_CARDS = [
  { key: 'total_scans', label: 'Total Scans', icon: '🔍', color: 'from-cyan-500/20 to-cyan-400/5', accent: '#00E5FF' },
  { key: 'total_assets', label: 'Assets Discovered', icon: '🌐', color: 'from-indigo-500/20 to-indigo-400/5', accent: '#7C4DFF' },
  { key: 'quantum_safe_pct', label: 'Quantum Safe %', icon: '🛡️', color: 'from-emerald-500/20 to-emerald-400/5', accent: '#00E676', suffix: '%' },
  { key: 'vulnerable_count', label: 'Vulnerable', icon: '⚠️', color: 'from-red-500/20 to-red-400/5', accent: '#FF1744' },
];

export default function Dashboard() {
  const { data: stats, isLoading } = useDashboardStats();

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-header">Dashboard</h1>
          <p className="text-gray-400 mt-1">Quantum-Proof Cryptographic Scanner Overview</p>
        </div>
        <Link to="/scan/new" className="btn-primary">
          + New Scan
        </Link>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {STAT_CARDS.map(({ key, label, icon, color, accent, suffix }) => (
          <div
            key={key}
            className="stat-card"
            style={{ '--accent-color': accent }}
          >
            <div className={`absolute inset-0 bg-gradient-to-br ${color} opacity-50`} />
            <div className="relative">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">{label}</span>
                <span className="text-2xl">{icon}</span>
              </div>
              <p className="text-3xl font-extrabold text-white">
                {isLoading ? (
                  <span className="inline-block w-16 h-8 bg-white/5 rounded animate-pulse" />
                ) : (
                  <>
                    {stats?.[key]?.toLocaleString() ?? '0'}
                    {suffix && <span className="text-lg text-gray-400">{suffix}</span>}
                  </>
                )}
              </p>
            </div>
          </div>
        ))}
      </div>

      {/* Charts + Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart */}
        <div className="lg:col-span-1">
          <CipherChart assets={stats?.recent_scans?.flatMap(() => []) || []} type="status" />
        </div>

        {/* Recent Scans */}
        <div className="lg:col-span-2">
          <div className="glass-card">
            <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between">
              <h3 className="section-title">
                <span>📋</span> Recent Scans
              </h3>
            </div>
            <div className="overflow-hidden">
              {isLoading ? (
                <div className="p-8 text-center text-gray-500">Loading...</div>
              ) : !stats?.recent_scans?.length ? (
                <div className="p-8 text-center">
                  <p className="text-gray-500 mb-4">No scans yet. Start your first scan!</p>
                  <Link to="/scan/new" className="btn-primary text-sm">
                    🔍 Start Scanning
                  </Link>
                </div>
              ) : (
                <table className="w-full">
                  <thead>
                    <tr className="table-header">
                      <th className="px-6 py-3 text-left">Target</th>
                      <th className="px-6 py-3 text-left">Status</th>
                      <th className="px-6 py-3 text-left">Assets</th>
                      <th className="px-6 py-3 text-left">Safe</th>
                      <th className="px-6 py-3 text-left">Date</th>
                      <th className="px-6 py-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recent_scans.map((scan) => (
                      <tr key={scan.id} className="table-row">
                        <td className="px-6 py-4">
                          <span className="font-medium text-gray-200 font-mono text-sm">{scan.target}</span>
                        </td>
                        <td className="px-6 py-4">
                          <StatusChip status={scan.status} />
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-400">{scan.total_assets}</td>
                        <td className="px-6 py-4 text-sm text-emerald-400 font-mono">{scan.quantum_safe_count}</td>
                        <td className="px-6 py-4 text-xs text-gray-500">
                          {new Date(scan.created_at).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <Link
                            to={`/scan/${scan.id}`}
                            className="text-sm text-cyan-400 hover:text-cyan-300 font-medium"
                          >
                            View →
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatusChip({ status }) {
  const config = {
    queued: 'badge-queued',
    running: 'badge-running',
    completed: 'badge-safe',
    failed: 'badge-vulnerable',
  };
  return (
    <span className={config[status] || 'badge-queued'}>
      {status}
    </span>
  );
}
