import React, { useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Milestone,
  Download,
  Clock,
  ShieldAlert,
  ShieldCheck,
  Lock,
  ArrowRight,
  Copy,
  Check,
  FileCheck2,
  SlidersHorizontal,
  PlusCircle,
  AlertCircle,
  FileCode,
  Globe,
  CheckCircle2,
  FolderGit2,
  History,
} from 'lucide-react';
import { getScans, getMigrationPlan, exportIssues } from '../api/client';
import { useProjectScope } from '../context/ProjectScopeContext';
import toast from 'react-hot-toast';

export default function MigrationRoadmap() {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlScanId = searchParams.get('scanId') || searchParams.get('scan_id');
  const { activeProject, activeProjectId, selectProject, openHistory, scansList, isLoadingScans } = useProjectScope();
  const [activeTab, setActiveTab] = useState('ALL');
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [copiedFileIndex, setCopiedFileIndex] = useState(null);

  // Active scan is strictly the globally active project or URL param
  const activeScan = activeProjectId || urlScanId || (scansList[0]?.id || null);

  // Active project metadata
  const currentProject = scansList.find((s) => s.id === activeScan) || activeProject || null;

  // Synchronize URL if scanId query param is present on direct navigation
  React.useEffect(() => {
    if (urlScanId && urlScanId !== activeProjectId && scansList.some((s) => s.id === urlScanId)) {
      selectProject(urlScanId);
    }
  }, [urlScanId, activeProjectId, scansList, selectProject]);

  const handleSelectProject = (newScanId) => {
    selectProject(newScanId);
    setSearchParams({ scanId: newScanId });
  };

  // Load migration plan for active scan
  const { data: planData, isLoading: isLoadingPlan } = useQuery({
    queryKey: ['migration-plan', activeScan],
    queryFn: () => (activeScan ? getMigrationPlan(activeScan) : null),
    enabled: !!activeScan,
  });

  const actions = planData?.actions || [];

  const filteredActions = actions.filter((a) => {
    if (activeTab === 'ALL') return true;
    return a.priority?.startsWith(activeTab);
  });

  const p0Count = planData?.p0_critical_count ?? actions.filter((a) => a.priority?.startsWith('P0')).length;
  const p1Count = planData?.p1_high_count ?? actions.filter((a) => a.priority?.startsWith('P1')).length;
  const p2Count = actions.filter((a) => a.priority?.startsWith('P2')).length;
  const p3Count = actions.filter((a) => a.priority?.startsWith('P3')).length;
  const totalEffort = planData?.total_estimated_effort_hours ?? planData?.total_effort_hours ?? actions.reduce((sum, a) => sum + (a.estimated_effort_hours || 0), 0);

  const copyCode = (snippet, index) => {
    navigator.clipboard.writeText(snippet);
    setCopiedIndex(index);
    toast.success('Code remediation snippet copied!');
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const copyFilePath = (path, index) => {
    navigator.clipboard.writeText(path);
    setCopiedFileIndex(index);
    toast.success('File path copied to clipboard!');
    setTimeout(() => setCopiedFileIndex(null), 2000);
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
      const count = res.total_issues ?? res.exported_issues_count ?? (res.issues ? res.issues.length : 0);
      toast.success(`Exported ${count} issues!`);
    } catch (err) {
      toast.error('Failed to export remediation issues');
    }
  };

  const getPriorityBadge = (priority) => {
    if (!priority) return null;
    if (priority.startsWith('P0')) {
      return <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">P0 • CRITICAL (HNDL)</span>;
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
    <div className="space-y-6 animate-fade-in">
      {/* Target Project Header Bar (Strict Single-Project Scope) */}
      <div className="glass-card p-4 border border-cyan-500/20 bg-gradient-to-r from-navy-950 via-navy-900 to-navy-950 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3.5">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-400/20 text-cyan-400">
              <FolderGit2 className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
                  Target Project
                </span>
                {currentProject && (
                  <span className="text-xs text-gray-400 font-mono">
                    Scanned on {new Date(currentProject.created_at).toLocaleDateString()} at{' '}
                    {new Date(currentProject.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                )}
              </div>
              <h2 className="text-lg font-bold text-white font-mono mt-0.5 flex items-center gap-2">
                <span>{currentProject?.target || 'Select a Scan Target'}</span>
                {currentProject?.vulnerable_count > 0 ? (
                  <span className="text-xs font-sans px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1 font-semibold">
                    <ShieldAlert className="w-3 h-3" />
                    {currentProject.vulnerable_count} Vulnerabilities
                  </span>
                ) : (
                  <span className="text-xs font-sans px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 font-semibold">
                    <CheckCircle2 className="w-3 h-3" />
                    Quantum-Safe
                  </span>
                )}
              </h2>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-400 font-medium">Switch Target:</span>
              <select
                value={activeScan || ''}
                onChange={(e) => handleSelectProject(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-navy-900 border border-cyan-500/30 text-xs text-cyan-200 focus:outline-none focus:border-cyan-400 max-w-[280px] truncate cursor-pointer"
              >
                {scansList.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target} • {s.vulnerable_count ?? 0} vuln ({s.id.substring(0, 8)})
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={openHistory}
              className="text-xs py-1.5 px-3 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-400/30 text-cyan-300 transition-all flex items-center gap-1.5 cursor-pointer"
              title="Open Project History Drawer"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              <span>Project History</span>
            </button>

            <button
              onClick={handleExportIssues}
              disabled={!activeScan || actions.length === 0}
              className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Issues JSON</span>
            </button>
          </div>
        </div>
      </div>

      {/* Page Title */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
            STRATEGIC MIGRATION
          </span>
          <span className="text-xs text-gray-400 font-mono">NIST FIPS 203 / CNSA 2.0</span>
        </div>
        <h1 className="page-header flex items-center gap-2.5">
          <Milestone className="w-6 h-6 text-cyan-400" />
          <span>Post-Quantum Migration Roadmap</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Prioritized engineering action plans, code-level replacements (FIPS 203/204), and developer remediation tasks for <strong className="text-cyan-300 font-mono">{currentProject?.target || 'selected project'}</strong>.
        </p>
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
      {isLoadingScans || isLoadingPlan ? (
        <div className="glass-card p-16 text-center text-gray-400">
          <div className="animate-spin inline-block w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mb-3" />
          <p className="text-sm font-medium text-gray-300">Generating prioritized migration roadmap...</p>
          <p className="text-xs text-gray-500 mt-1">Cross-referencing NIST FIPS 203/204 standards with discovered cryptographic primitives...</p>
        </div>
      ) : scansList.length === 0 ? (
        <div className="glass-card p-12 text-center text-gray-400 space-y-3">
          <AlertCircle className="w-8 h-8 text-gray-600 mx-auto" />
          <h3 className="text-base font-semibold text-white">No Cryptographic Discovery Scans Found</h3>
          <p className="text-xs text-gray-500 max-w-md mx-auto">
            Run a source code, network endpoint, or container scan from Central Command to generate actionable Post-Quantum migration roadmaps.
          </p>
          <Link to="/scan/new" className="btn-primary text-xs inline-flex items-center gap-1.5 mt-2">
            <PlusCircle className="w-3.5 h-3.5" />
            <span>Launch New Scan</span>
          </Link>
        </div>
      ) : actions.length === 0 ? (
        <div className="glass-card p-12 text-center text-gray-400 space-y-2">
          <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
          <h3 className="text-base font-semibold text-white">No Quantum Vulnerabilities Requiring Remediation</h3>
          <p className="text-xs text-gray-500 max-w-md mx-auto">
            All cryptographic primitives detected in this scan target meet post-quantum safety criteria or use sufficient symmetric key lengths.
          </p>
        </div>
      ) : filteredActions.length === 0 ? (
        <div className="glass-card p-12 text-center text-gray-500">
          No migration actions found for priority tier "{activeTab}". Select another tab above to review other remediation items.
        </div>
      ) : (
        <div className="space-y-4">
          {filteredActions.map((action, idx) => (
            <div
              key={idx}
              className="glass-card p-6 border border-white/5 hover:border-cyan-500/30 transition-all space-y-4"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-white/5 pb-3">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-3">
                    {getPriorityBadge(action.priority)}
                    <h3 className="text-base font-bold text-white">
                      {action.asset_name}
                    </h3>
                  </div>

                  {/* Exact File Provenance / Location */}
                  <div className="flex flex-wrap items-center gap-2 pt-0.5">
                    {action.file_path ? (
                      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-navy-950 border border-cyan-500/20 text-xs font-mono text-cyan-300">
                        <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="font-semibold">{action.file_path}</span>
                        {action.line_number && (
                          <span className="text-amber-400 font-bold bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                            Line {action.line_number}
                          </span>
                        )}
                        <button
                          onClick={() => copyFilePath(action.file_path, idx)}
                          className="ml-1 text-gray-500 hover:text-cyan-300 transition-colors"
                          title="Copy file path"
                        >
                          {copiedFileIndex === idx ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    ) : action.hostname ? (
                      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-navy-950 border border-sky-500/20 text-xs font-mono text-sky-300">
                        <Globe className="w-3.5 h-3.5 text-sky-400" />
                        <span>{action.hostname}:{action.port || 443}</span>
                      </div>
                    ) : null}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs text-gray-400">Est. Effort:</span>
                  <span className="font-mono text-xs font-bold text-cyan-300 bg-cyan-500/10 px-2.5 py-1 rounded border border-cyan-400/20">
                    {action.estimated_effort_hours} Hours
                  </span>
                </div>
              </div>

              {/* Developer Action Plan Box */}
              <div className="p-3.5 rounded-lg bg-navy-950/80 border border-cyan-500/20 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-cyan-400">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Developer Remediation Playbook</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-xs">
                  <div className="p-2.5 rounded bg-black/40 border border-white/5 space-y-1">
                    <span className="text-gray-500 font-mono text-[10px] font-bold block uppercase tracking-wider">Step 1 • Target Codebase</span>
                    <p className="text-gray-300">
                      {action.file_path ? (
                        <>Open <span className="font-mono text-cyan-300">{action.file_path}</span> at line <strong className="text-amber-400">{action.line_number || '1'}</strong></>
                      ) : (
                        <>Inspect TLS listener on <span className="font-mono text-sky-300">{action.hostname || 'endpoint'}</span></>
                      )}
                    </p>
                  </div>
                  <div className="p-2.5 rounded bg-black/40 border border-white/5 space-y-1">
                    <span className="text-gray-500 font-mono text-[10px] font-bold block uppercase tracking-wider">Step 2 • Deprecate Classical</span>
                    <p className="text-gray-300">
                      Remove classical <span className="font-mono text-rose-400 font-semibold">{action.current_algorithm}</span> and inject PQC provider.
                    </p>
                  </div>
                  <div className="p-2.5 rounded bg-black/40 border border-white/5 space-y-1">
                    <span className="text-gray-500 font-mono text-[10px] font-bold block uppercase tracking-wider">Step 3 • Implement Standard</span>
                    <p className="text-gray-300">
                      Migrate to <strong className="text-emerald-400 font-mono">{action.target_algorithm}</strong> ({action.target_standard}).
                    </p>
                  </div>
                </div>
              </div>

              {/* Algorithm Transition Badge */}
              <div className="flex items-center gap-3 text-sm">
                <span className="px-2.5 py-1 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 font-mono text-xs">
                  {action.current_algorithm}
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-gray-400" />
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
                      onClick={() => copyCode(action.code_remediation_snippet, idx)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedIndex === idx ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedIndex === idx ? 'Copied!' : 'Copy Snippet'}</span>
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
