import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getScans, getMigrationPlan, exportIssues } from '../api/client';
import toast from 'react-hot-toast';

export default function MigrationRoadmap() {
  const [selectedScanId, setSelectedScanId] = useState('');
  const [activeTab, setActiveTab] = useState('ALL');

  // Load scans list to populate scan selector
  const { data: scansData, isLoading: isLoadingScans } = useQuery({
    queryKey: ['scans-list'],
    queryFn: () => getScans({ limit: 20 }),
  });

  const scans = scansData?.items || [];
  const activeScan = selectedScanId || (scans.length > 0 ? scans[0].id : null);

  // Load migration plan for active scan
  const { data: planData, isLoading: isLoadingPlan } = useQuery({
    queryKey: ['migration-plan', activeScan],
    queryFn: () => (activeScan ? getMigrationPlan(activeScan) : null),
    enabled: !!activeScan,
  });

  const actions = planData?.actions || [];

  const filteredActions = actions.filter((a) => {
    if (activeTab === 'ALL') return true;
    return a.priority.startsWith(activeTab);
  });

  const p0Count = actions.filter((a) => a.priority.startsWith('P0')).length;
  const p1Count = actions.filter((a) => a.priority.startsWith('P1')).length;
  const p2Count = actions.filter((a) => a.priority.startsWith('P2')).length;
  const p3Count = actions.filter((a) => a.priority.startsWith('P3')).length;
  const totalEffort = planData?.total_effort_hours || actions.reduce((sum, a) => sum + (a.estimated_effort_hours || 0), 0);

  const copyCode = (snippet) => {
    navigator.clipboard.writeText(snippet);
    toast.success('Code remediation snippet copied!');
  };

  const handleExportIssues = async () => {
    if (!activeScan) return;
    try {
      const res = await exportIssues(activeScan);
      const blob = new Blob([JSON.stringify(res, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `remediation_issues_scan_${activeScan.substring(0, 8)}.json`;
      link.click();
      window.URL.revokeObjectURL(url);
      toast.success(`Exported ${res.exported_issues_count || 0} issues!`);
    } catch (err) {
      toast.error('Failed to export remediation issues');
    }
  };

  const getPriorityBadge = (priority) => {
    if (priority.startsWith('P0')) {
      return <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/40">P0 • CRITICAL (HNDL)</span>;
    }
    if (priority.startsWith('P1')) {
      return <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">P1 • HIGH (Signatures)</span>;
    }
    if (priority.startsWith('P2')) {
      return <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40">P2 • MEDIUM (Symmetric)</span>;
    }
    return <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-gray-500/20 text-gray-400 border border-gray-500/40">P3 • LOW (Agility)</span>;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <span>🚀</span> Post-Quantum Migration Roadmap
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Prioritized engineering action plans, code-level replacements (FIPS 203/204), and developer remediation tasks.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Scan selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-400">Scan:</span>
            <select
              value={activeScan || ''}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-navy-900 border border-white/10 text-xs text-white focus:outline-none focus:border-cyan-400/50"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target} ({s.id.substring(0, 8)})
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={handleExportIssues}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-black transition-colors shadow-glow-cyan"
          >
            📦 Export Issues JSON
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="stat-card">
          <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">Total Effort</div>
          <div className="text-2xl font-bold text-cyan-400 font-mono mt-1">{totalEffort} hrs</div>
          <div className="text-[10px] text-gray-500 mt-1">Estimated engineering hours</div>
        </div>
        <div className="stat-card">
          <div className="text-[11px] font-semibold text-red-400 uppercase tracking-wider">P0 Critical</div>
          <div className="text-2xl font-bold text-red-400 font-mono mt-1">{p0Count}</div>
          <div className="text-[10px] text-gray-500 mt-1">HNDL Key Encapsulation</div>
        </div>
        <div className="stat-card">
          <div className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider">P1 High</div>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-1">{p1Count}</div>
          <div className="text-[10px] text-gray-500 mt-1">Signatures & Authentication</div>
        </div>
        <div className="stat-card">
          <div className="text-[11px] font-semibold text-blue-400 uppercase tracking-wider">P2 Medium</div>
          <div className="text-2xl font-bold text-blue-400 font-mono mt-1">{p2Count}</div>
          <div className="text-[10px] text-gray-500 mt-1">Symmetric 256-bit upgrades</div>
        </div>
        <div className="stat-card">
          <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">P3 Low</div>
          <div className="text-2xl font-bold text-gray-400 font-mono mt-1">{p3Count}</div>
          <div className="text-[10px] text-gray-500 mt-1">Hashes & Crypto Agility</div>
        </div>
      </div>

      {/* Priority Tabs */}
      <div className="flex items-center gap-2 border-b border-white/5 pb-2">
        {[
          { id: 'ALL', label: `All Migrations (${actions.length})` },
          { id: 'P0', label: `P0 Critical (${p0Count})` },
          { id: 'P1', label: `P1 High (${p1Count})` },
          { id: 'P2', label: `P2 Medium (${p2Count})` },
          { id: 'P3', label: `P3 Low (${p3Count})` },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === tab.id
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-white/5'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Migration Actions List */}
      {isLoadingPlan ? (
        <div className="p-16 text-center text-gray-400">
          <div className="animate-spin inline-block w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mb-3" />
          <p>Generating prioritized migration roadmap...</p>
        </div>
      ) : filteredActions.length === 0 ? (
        <div className="glass-card p-12 text-center text-gray-500">
          No migration actions found for this priority category.
        </div>
      ) : (
        <div className="space-y-4">
          {filteredActions.map((action, idx) => (
            <div
              key={idx}
              className="glass-card p-6 border border-white/5 hover:border-cyan-500/30 transition-all space-y-4"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-white/5 pb-3">
                <div className="flex items-center gap-3">
                  {getPriorityBadge(action.priority)}
                  <h3 className="text-base font-bold text-white">
                    {action.asset_name}
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-400">Est. Effort:</span>
                  <span className="font-mono text-xs font-bold text-cyan-300">
                    {action.estimated_effort_hours} Hours
                  </span>
                </div>
              </div>

              {/* Algorithm Transition Badge */}
              <div className="flex items-center gap-3 text-sm">
                <span className="px-2.5 py-1 rounded bg-red-500/10 border border-red-500/30 text-red-400 font-mono text-xs">
                  {action.current_algorithm}
                </span>
                <span className="text-gray-500">➔</span>
                <span className="px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-xs font-bold">
                  {action.target_algorithm}
                </span>
                <span className="text-xs text-gray-400">
                  Standard: <strong className="text-white">{action.target_standard}</strong>
                </span>
              </div>

              {/* Urgency Reason */}
              <div className="text-xs text-gray-300 bg-navy-950/60 p-3 rounded-lg border border-white/5">
                <strong className="text-amber-400">Urgency: </strong> {action.urgency_reason}
              </div>

              {/* Remediation Snippet */}
              {action.code_remediation_snippet && (
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">
                      Code Remediation Snippet (Python / liboqs)
                    </span>
                    <button
                      onClick={() => copyCode(action.code_remediation_snippet)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 underline"
                    >
                      Copy Snippet
                    </button>
                  </div>
                  <pre className="p-3 rounded-lg bg-black/70 font-mono text-xs text-emerald-300 overflow-x-auto border border-white/5">
                    {action.code_remediation_snippet}
                  </pre>
                </div>
              )}

              {/* TLS / Config changes */}
              {action.configuration_changes && (
                <div>
                  <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider block mb-1">
                    TLS & Server Configuration
                  </span>
                  <pre className="p-2.5 rounded bg-black/50 font-mono text-xs text-cyan-200 overflow-x-auto border border-white/5">
                    {action.configuration_changes}
                  </pre>
                </div>
              )}

              {/* Checklist */}
              {action.testing_checklist && action.testing_checklist.length > 0 && (
                <div>
                  <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider block mb-1.5">
                    Verification & Testing Checklist
                  </span>
                  <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-gray-400">
                    {action.testing_checklist.map((item, cIdx) => (
                      <li key={cIdx} className="flex items-center gap-2">
                        <input type="checkbox" className="rounded bg-navy-900 border-white/10 text-cyan-400" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
