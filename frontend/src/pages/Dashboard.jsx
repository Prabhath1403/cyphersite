/**
 * Dashboard — Enterprise Post-Quantum Cryptography & CBOM Command Center.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import {
  Scan,
  Layers,
  ShieldCheck,
  AlertTriangle,
  Plus,
  ArrowRight,
  Activity,
  Globe,
  Code,
  Box,
  Binary,
  Clock,
  ExternalLink,
  ShieldAlert,
  FileCheck2,
} from 'lucide-react';
import { useDashboardStats } from '../hooks/useScanResults';
import CipherChart from '../components/CipherChart';

const STAT_CARDS = [
  {
    key: 'total_scans',
    label: 'Total Scans',
    icon: Scan,
    color: 'from-cyan-500/20 to-cyan-400/5',
    accent: '#00E5FF',
    iconColor: 'text-cyan-400',
    description: 'Autonomous multi-modal runs',
  },
  {
    key: 'total_assets',
    label: 'Assets Discovered',
    icon: Layers,
    color: 'from-indigo-500/20 to-indigo-400/5',
    accent: '#818CF8',
    iconColor: 'text-indigo-400',
    description: 'Ciphers, keys, certificates',
  },
  {
    key: 'quantum_safe_pct',
    label: 'Quantum Safe Posture',
    icon: ShieldCheck,
    color: 'from-emerald-500/20 to-emerald-400/5',
    accent: '#10B981',
    suffix: '%',
    iconColor: 'text-emerald-400',
    description: 'NIST FIPS 203/204 verified',
  },
  {
    key: 'vulnerable_count',
    label: 'Shor / Grover Exposure',
    icon: AlertTriangle,
    color: 'from-rose-500/20 to-rose-400/5',
    accent: '#F43F5E',
    iconColor: 'text-rose-400',
    description: 'Immediate migration required',
  },
];

export default function Dashboard() {
  const { data: stats, isLoading } = useDashboardStats();

  const totalAssets = stats?.total_assets || 0;
  const vulnerableCount = stats?.vulnerable_count || 0;
  const quantumSafeCount = Math.round((totalAssets * (stats?.quantum_safe_pct || 0)) / 100);
  const hybridCount = Math.max(0, totalAssets - vulnerableCount - quantumSafeCount);

  const summaryCounts = {
    'Quantum Safe': quantumSafeCount,
    'Hybrid Ready': hybridCount,
    'Vulnerable': vulnerableCount,
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header with Title & Primary CTA */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
              CENTRAL COMMAND
            </span>
            <span className="text-xs text-gray-400 font-mono">PNB CyberSec Platform</span>
          </div>
          <h1 className="page-header">Cryptographic Posture & Migration Radar</h1>
          <p className="text-sm text-gray-400 mt-1">
            Real-time Shor algorithm vulnerability detection, Mosca Theorem modeling, and CycloneDX CBOM intelligence.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link to="/roadmap" className="btn-secondary text-xs">
            <FileCheck2 className="w-4 h-4 text-gray-300" />
            <span>Migration Roadmap</span>
          </Link>
          <Link to="/scan/new" className="btn-primary text-xs">
            <Plus className="w-4 h-4" />
            <span>New Scan</span>
          </Link>
        </div>
      </div>

      {/* Threat Horizon & Mosca Condition Banner */}
      <div className="rounded-xl border border-amber-500/30 bg-gradient-to-r from-amber-500/10 via-rose-500/5 to-transparent p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-amber-500/20 text-amber-300 mt-0.5">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-white">
                Mosca Theorem Risk Threshold Exceeded
              </span>
              <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-amber-400/20 text-amber-300 border border-amber-400/30">
                X + Y &gt; Z
              </span>
            </div>
            <p className="text-xs text-gray-300 mt-1 max-w-2xl">
              Harvest Now, Decrypt Later (HNDL) window active. RSA and ECC keys in financial data channels exceed secure shelf-life limits before expected CRQC quantum threat arrival.
            </p>
          </div>
        </div>
        <Link
          to="/roadmap"
          className="text-xs font-semibold text-amber-300 hover:text-amber-200 inline-flex items-center gap-1.5 whitespace-nowrap"
        >
          <span>View P0 Mitigation Plan</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {STAT_CARDS.map(({ key, label, icon: Icon, color, accent, suffix, iconColor, description }) => (
          <div
            key={key}
            className="stat-card group"
            style={{ '--accent-color': accent }}
          >
            <div className={`absolute inset-0 bg-gradient-to-br ${color} opacity-40 group-hover:opacity-60 transition-opacity`} />
            <div className="relative">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">{label}</span>
                <div className={`p-2 rounded-lg bg-white/[0.04] border border-white/[0.06] ${iconColor}`}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>
              <p className="text-3xl font-extrabold text-white font-mono tracking-tight">
                {isLoading ? (
                  <span className="inline-block w-20 h-8 bg-white/5 rounded animate-pulse" />
                ) : (
                  <>
                    {stats?.[key]?.toLocaleString() ?? '0'}
                    {suffix && <span className="text-lg text-gray-400 font-sans">{suffix}</span>}
                  </>
                )}
              </p>
              <p className="text-[11px] text-gray-400 mt-2">{description}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Charts + Recent Scans Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Cipher Distribution Chart (Fixed & Connected) */}
        <div className="lg:col-span-1 h-full">
          <CipherChart summaryCounts={summaryCounts} type="status" />
        </div>

        {/* Recent Scans Table */}
        <div className="lg:col-span-2">
          <div className="glass-card flex flex-col h-full">
            <div className="px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
              <h3 className="section-title">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span>Recent Discovery Scans</span>
              </h3>
              <Link
                to="/inventory"
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1"
              >
                <span>View Inventory</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            <div className="overflow-x-auto flex-1">
              {isLoading ? (
                <div className="p-12 text-center text-gray-500">
                  <div className="inline-block w-6 h-6 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin mb-2" />
                  <p className="text-xs">Querying scan registry...</p>
                </div>
              ) : !stats?.recent_scans?.length ? (
                <div className="p-12 text-center">
                  <Scan className="w-8 h-8 text-gray-600 mx-auto mb-3" />
                  <p className="text-gray-400 text-sm mb-4">No discovery scans recorded yet.</p>
                  <Link to="/scan/new" className="btn-primary text-xs">
                    <Plus className="w-3.5 h-3.5" />
                    <span>Run Your First Scan</span>
                  </Link>
                </div>
              ) : (
                <table className="w-full">
                  <thead>
                    <tr className="table-header">
                      <th className="px-5 py-3 text-left">Target / Scope</th>
                      <th className="px-5 py-3 text-left">Type</th>
                      <th className="px-5 py-3 text-left">Status</th>
                      <th className="px-5 py-3 text-left">Assets</th>
                      <th className="px-5 py-3 text-left">Date</th>
                      <th className="px-5 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recent_scans.map((scan) => (
                      <tr key={scan.id} className="table-row">
                        <td className="px-5 py-3.5">
                          <div className="flex flex-col">
                            <span className="font-medium text-gray-200 font-mono text-xs truncate max-w-xs" title={scan.target}>
                              {scan.target}
                            </span>
                            <span className="text-[10px] text-gray-400 font-mono">
                              ID: {scan.id.substring(0, 8)} • {scan.scan_depth}
                            </span>
                          </div>
                        </td>
                        <td className="px-5 py-3.5">
                          <ScanTypeBadge type={scan.scan_type} />
                        </td>
                        <td className="px-5 py-3.5">
                          <StatusChip status={scan.status} />
                        </td>
                        <td className="px-5 py-3.5">
                          <div className="text-xs font-mono">
                            <span className="text-white font-semibold">{scan.total_assets}</span>
                            {scan.vulnerable_count > 0 && (
                              <span className="text-rose-400 text-[10px] ml-1.5">
                                ({scan.vulnerable_count} vuln)
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-5 py-3.5 text-xs text-gray-400 whitespace-nowrap">
                          {new Date(scan.created_at).toLocaleDateString(undefined, {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })}
                        </td>
                        <td className="px-5 py-3.5 text-right">
                          <Link
                            to={`/scan/${scan.id}`}
                            className="inline-flex items-center gap-1 text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors"
                          >
                            <span>Inspect</span>
                            <ArrowRight className="w-3 h-3" />
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
    queued: { cls: 'badge-queued', label: 'Queued' },
    running: { cls: 'badge-running', label: 'Scanning' },
    completed: { cls: 'badge-safe', label: 'Completed' },
    failed: { cls: 'badge-vulnerable', label: 'Failed' },
  };
  const item = config[status] || { cls: 'badge-queued', label: status };
  return (
    <span className={item.cls}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {item.label}
    </span>
  );
}

function ScanTypeBadge({ type }) {
  switch (type) {
    case 'source':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
          <Code className="w-3 h-3" /> Source
        </span>
      );
    case 'container':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
          <Box className="w-3 h-3" /> Container
        </span>
      );
    case 'binary':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <Binary className="w-3 h-3" /> Binary
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
          <Globe className="w-3 h-3" /> Network
        </span>
      );
  }
}
