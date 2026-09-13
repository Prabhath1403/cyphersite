import React, { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Database,
  RefreshCw,
  Plus,
  Search,
  Filter,
  Download,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  ChevronLeft,
  ChevronRight,
  Sparkles,
  GitPullRequest,
  X,
  Copy,
  Check,
  ExternalLink,
  Code2,
  Cpu,
  ShieldAlert,
  FileCode,
  Layers,
  Send,
  SlidersHorizontal,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { getCryptoAssets, explainFinding, getIssuePreview, publishGitHubIssue } from '../api/client';
import PQCBadge from '../components/PQCBadge';

export default function CryptoInventory() {
  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [primitiveFilter, setPrimitiveFilter] = useState('');
  const [sensitivityFilter, setSensitivityFilter] = useState('');

  // Sorting state
  const [sortField, setSortField] = useState('risk_score');
  const [sortOrder, setSortOrder] = useState('desc'); // 'asc' | 'desc'

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);

  // Selected asset for Slide-Over Drawer
  const [drawerAsset, setDrawerAsset] = useState(null);
  const [drawerTab, setDrawerTab] = useState('details'); // 'details' | 'ai' | 'remediation'

  // AI Explanation State
  const [explanationData, setExplanationData] = useState(null);
  const [isExplaining, setIsExplaining] = useState(false);

  // GitHub Remediation State
  const [issueData, setIssueData] = useState(null);
  const [isLoadingIssue, setIsLoadingIssue] = useState(false);
  const [repoOwner, setRepoOwner] = useState('');
  const [repoName, setRepoName] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [isPublishing, setIsPublishing] = useState(false);

  // Copy feedback state
  const [copiedKey, setCopiedKey] = useState(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['crypto-assets', sourceFilter, statusFilter, primitiveFilter],
    queryFn: () =>
      getCryptoAssets({
        limit: 200,
        source_type: sourceFilter || undefined,
        pqc_status: statusFilter || undefined,
        primitive: primitiveFilter || undefined,
      }),
  });

  const assets = data?.assets || [];

  // Filter and Sort
  const processedAssets = useMemo(() => {
    let result = assets.filter((item) => {
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        const match =
          item.name?.toLowerCase().includes(q) ||
          item.algorithm?.toLowerCase().includes(q) ||
          item.file_path?.toLowerCase().includes(q) ||
          item.hostname?.toLowerCase().includes(q) ||
          item.library?.toLowerCase().includes(q);
        if (!match) return false;
      }
      if (sensitivityFilter && (item.sensitivity || 'general').toLowerCase() !== sensitivityFilter.toLowerCase()) {
        return false;
      }
      return true;
    });

    result.sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];

      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = (bVal || '').toLowerCase();
        return sortOrder === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      }

      aVal = aVal == null ? -Infinity : aVal;
      bVal = bVal == null ? -Infinity : bVal;
      return sortOrder === 'asc' ? aVal - bVal : bVal - aVal;
    });

    return result;
  }, [assets, searchTerm, sensitivityFilter, sortField, sortOrder]);

  // Pagination slice
  const totalPages = Math.max(1, Math.ceil(processedAssets.length / pageSize));
  const paginatedAssets = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return processedAssets.slice(start, start + pageSize);
  }, [processedAssets, currentPage, pageSize]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const handleOpenDrawer = async (asset, initialTab = 'details') => {
    setDrawerAsset(asset);
    setDrawerTab(initialTab);

    if (initialTab === 'ai' || !explanationData) {
      loadExplanation(asset);
    }
    if (initialTab === 'remediation' || !issueData) {
      loadRemediation(asset);
    }
  };

  const loadExplanation = async (asset) => {
    setIsExplaining(true);
    try {
      const res = await explainFinding({ finding_id: asset.id });
      setExplanationData(res);
    } catch {
      toast.error('Failed to load AI explanation');
    } finally {
      setIsExplaining(false);
    }
  };

  const loadRemediation = async (asset) => {
    setIsLoadingIssue(true);
    try {
      const res = await getIssuePreview(asset.id);
      setIssueData(res);
    } catch {
      toast.error('Failed to load remediation preview');
    } finally {
      setIsLoadingIssue(false);
    }
  };

  const handlePublishIssue = async (e) => {
    e.preventDefault();
    if (!repoOwner || !repoName || !githubToken) {
      toast.error('Please enter repository owner, name, and GitHub token');
      return;
    }
    setIsPublishing(true);
    try {
      const res = await publishGitHubIssue({
        owner: repoOwner,
        repo: repoName,
        github_token: githubToken,
        title: issueData.title,
        body: issueData.body,
        labels: issueData.labels,
      });
      if (res.status === 'success') {
        toast.success(`GitHub issue published: #${res.issue_number || ''}`);
        setDrawerAsset(null);
      } else {
        toast.error(res.message || 'Publishing failed');
      }
    } catch {
      toast.error('Failed to publish GitHub Issue');
    } finally {
      setIsPublishing(false);
    }
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    toast.success('Copied to clipboard!');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const exportCSV = () => {
    if (!processedAssets.length) {
      toast.error('No assets to export');
      return;
    }
    const headers = ['ID', 'Name', 'Algorithm', 'Key Size', 'Primitive', 'Source', 'File/Host', 'Sensitivity', 'Status', 'Risk Score'];
    const rows = processedAssets.map((a) => [
      a.id,
      `"${a.name || ''}"`,
      `"${a.algorithm || ''}"`,
      a.key_size || '',
      a.primitive || '',
      a.source_type || '',
      `"${a.file_path || a.hostname || ''}"`,
      a.sensitivity || '',
      a.quantum_status || a.pqc_status || '',
      a.risk_score != null ? a.risk_score : '',
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ciphersight_inventory_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
    toast.success('Exported CSV inventory');
  };

  const exportJSON = () => {
    if (!processedAssets.length) {
      toast.error('No assets to export');
      return;
    }
    const blob = new Blob([JSON.stringify(processedAssets, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ciphersight_inventory_${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    toast.success('Exported JSON inventory');
  };

  const getSensitivityBadge = (sens) => {
    const s = (sens || 'general').toLowerCase();
    if (s === 'financial' || s === 'government_id') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/30 uppercase">{s}</span>;
    }
    if (s === 'authentication' || s === 'medical' || s === 'pii') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/30 uppercase">{s}</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-500/10 text-slate-400 border border-slate-500/20 uppercase">{s}</span>;
  };

  return (
    <div className="space-y-6 animate-fade-in relative">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
              CANONICAL REPOSITORY
            </span>
            <span className="text-xs text-gray-400 font-mono">CycloneDX 1.5 Taxonomy</span>
          </div>
          <h1 className="page-header flex items-center gap-2.5">
            <Database className="w-6 h-6 text-cyan-400" />
            <span>Cryptographic Asset Inventory</span>
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Normalized catalog of ciphers, key-lengths, cryptographic libraries, and AST call-sites discovered across the enterprise attack surface.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={exportCSV}
            className="btn-secondary text-xs py-2 px-3"
            title="Export filtered assets to CSV"
          >
            <Download className="w-3.5 h-3.5" />
            <span>CSV</span>
          </button>
          <button
            onClick={exportJSON}
            className="btn-secondary text-xs py-2 px-3"
            title="Export filtered assets to JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>JSON</span>
          </button>
          <button
            onClick={() => refetch()}
            className="btn-secondary text-xs py-2 px-3"
            title="Refresh inventory"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          <Link to="/scan/new" className="btn-primary text-xs py-2 px-3.5">
            <Plus className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </Link>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="glass-card p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {/* Search Input */}
        <div className="relative">
          <label className="block text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-1">
            Search
          </label>
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search name, algorithm, file..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-navy-900/90 border border-white/10 text-xs text-gray-100 placeholder-gray-500 focus:outline-none focus:border-cyan-400/50"
            />
          </div>
        </div>

        {/* Source Type Filter */}
        <div>
          <label className="block text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-1">
            Source Origin
          </label>
          <select
            value={sourceFilter}
            onChange={(e) => {
              setSourceFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full px-3 py-1.5 rounded-lg bg-navy-900/90 border border-white/10 text-xs text-gray-200 focus:outline-none focus:border-cyan-400/50"
          >
            <option value="">All Sources</option>
            <option value="source_code">Source Code</option>
            <option value="container">Container Image</option>
            <option value="binary">Compiled Binary</option>
            <option value="network">Network / TLS</option>
          </select>
        </div>

        {/* Quantum Status Filter */}
        <div>
          <label className="block text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-1">
            Quantum Status
          </label>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full px-3 py-1.5 rounded-lg bg-navy-900/90 border border-white/10 text-xs text-gray-200 focus:outline-none focus:border-cyan-400/50"
          >
            <option value="">All Statuses</option>
            <option value="VULNERABLE">Vulnerable (Shor/Grover)</option>
            <option value="HYBRID_READY">Reduced / Hybrid Ready</option>
            <option value="QUANTUM_SAFE">Quantum Safe (FIPS 203/204)</option>
          </select>
        </div>

        {/* Primitive Filter */}
        <div>
          <label className="block text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-1">
            Primitive
          </label>
          <select
            value={primitiveFilter}
            onChange={(e) => {
              setPrimitiveFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full px-3 py-1.5 rounded-lg bg-navy-900/90 border border-white/10 text-xs text-gray-200 focus:outline-none focus:border-cyan-400/50"
          >
            <option value="">All Primitives</option>
            <option value="asymmetric">Asymmetric (KEX / Sign)</option>
            <option value="symmetric">Symmetric (Cipher)</option>
            <option value="hash">Hash / Digest</option>
            <option value="mac">MAC / KDF</option>
            <option value="pqc">Post-Quantum</option>
          </select>
        </div>

        {/* Sensitivity Filter */}
        <div>
          <label className="block text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-1">
            Data Sensitivity
          </label>
          <select
            value={sensitivityFilter}
            onChange={(e) => {
              setSensitivityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full px-3 py-1.5 rounded-lg bg-navy-900/90 border border-white/10 text-xs text-gray-200 focus:outline-none focus:border-cyan-400/50"
          >
            <option value="">All Sensitivities</option>
            <option value="financial">Financial</option>
            <option value="authentication">Authentication</option>
            <option value="government_id">Government ID</option>
            <option value="medical">Medical</option>
            <option value="pii">PII</option>
            <option value="general">General</option>
          </select>
        </div>
      </div>

      {/* Main Table Grid */}
      <div className="glass-card overflow-hidden border border-white/[0.08]">
        {/* Table Controls Header */}
        <div className="px-5 py-3.5 border-b border-white/[0.06] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="text-gray-400">
            Showing <span className="text-white font-mono font-semibold">{paginatedAssets.length}</span> of{' '}
            <span className="text-white font-mono font-semibold">{processedAssets.length}</span> matching findings
            {assets.length !== processedAssets.length && (
              <span className="text-gray-500 ml-1">({assets.length} total)</span>
            )}
          </div>

          <div className="flex items-center gap-3">
            <span className="text-gray-500">Rows per page:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setCurrentPage(1);
              }}
              className="px-2 py-1 rounded bg-navy-900 border border-white/10 text-gray-300 focus:outline-none text-xs"
            >
              <option value={10}>10</option>
              <option value={15}>15</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
            </select>
          </div>
        </div>

        {isLoading ? (
          <div className="p-16 text-center text-gray-400">
            <div className="inline-block w-6 h-6 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin mb-3" />
            <p className="text-xs">Loading canonical cryptography catalog...</p>
          </div>
        ) : paginatedAssets.length === 0 ? (
          <div className="p-16 text-center text-gray-500">
            <Layers className="w-8 h-8 text-gray-600 mx-auto mb-2" />
            <p className="text-sm font-medium text-gray-300">No cryptographic findings match your criteria</p>
            <p className="text-xs text-gray-500 mt-1">Try broadening your search term or filter parameters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="table-header select-none">
                  <th
                    className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                    onClick={() => handleSort('name')}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Finding Name</span>
                      <SortIcon field="name" currentField={sortField} order={sortOrder} />
                    </div>
                  </th>
                  <th
                    className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                    onClick={() => handleSort('algorithm')}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Algorithm & Key</span>
                      <SortIcon field="algorithm" currentField={sortField} order={sortOrder} />
                    </div>
                  </th>
                  <th
                    className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                    onClick={() => handleSort('primitive')}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Primitive</span>
                      <SortIcon field="primitive" currentField={sortField} order={sortOrder} />
                    </div>
                  </th>
                  <th className="py-3 px-4">Provenance & Path</th>
                  <th className="py-3 px-4">Sensitivity</th>
                  <th
                    className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                    onClick={() => handleSort('pqc_status')}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Quantum Posture</span>
                      <SortIcon field="pqc_status" currentField={sortField} order={sortOrder} />
                    </div>
                  </th>
                  <th
                    className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                    onClick={() => handleSort('risk_score')}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Risk Score</span>
                      <SortIcon field="risk_score" currentField={sortField} order={sortOrder} />
                    </div>
                  </th>
                  <th className="py-3 px-4 text-right">Quick Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.05] text-xs">
                {paginatedAssets.map((asset) => (
                  <tr
                    key={asset.id}
                    onClick={() => handleOpenDrawer(asset, 'details')}
                    className="table-row cursor-pointer group hover:bg-cyan-500/[0.03]"
                  >
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white group-hover:text-cyan-300 transition-colors">
                        {asset.name}
                      </div>
                      {asset.usage && (
                        <div className="text-[10px] text-gray-500 font-mono mt-0.5">
                          Usage: {asset.usage}
                        </div>
                      )}
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 font-mono">
                        <span className="font-bold text-cyan-400">{asset.algorithm || 'N/A'}</span>
                        {asset.key_size && (
                          <span className="text-[10px] px-1 rounded bg-white/5 text-gray-400">
                            {asset.key_size}b
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-4 text-gray-300 capitalize font-mono">
                      {asset.primitive || 'standard'}
                    </td>

                    <td className="py-3 px-4">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.04] text-gray-300 capitalize font-mono">
                        {asset.source_type?.replace('_', ' ')}
                      </span>
                      <div
                        className="text-gray-400 font-mono text-[10px] truncate max-w-xs mt-1"
                        title={asset.file_path || asset.hostname}
                      >
                        {asset.file_path
                          ? `${asset.file_path}${asset.line_number ? `:${asset.line_number}` : ''}`
                          : asset.hostname || '—'}
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      {getSensitivityBadge(asset.sensitivity)}
                    </td>

                    <td className="py-3 px-4">
                      <PQCBadge status={asset.quantum_status || asset.pqc_status} size="sm" />
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-14 bg-navy-950 rounded-full h-1.5 overflow-hidden border border-white/5">
                          <div
                            className={`h-full rounded-full transition-all ${
                              (asset.risk_score || 0) >= 70
                                ? 'bg-rose-500'
                                : (asset.risk_score || 0) >= 40
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, asset.risk_score || 0)}%` }}
                          />
                        </div>
                        <span className="font-mono font-bold text-xs text-gray-200">
                          {asset.risk_score != null ? Math.round(asset.risk_score) : '—'}
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleOpenDrawer(asset, 'ai')}
                          className="px-2 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 transition-colors inline-flex items-center gap-1"
                          title="Shor/Grover AI Analysis"
                        >
                          <Sparkles className="w-3 h-3" />
                          <span>Explain</span>
                        </button>
                        <button
                          onClick={() => handleOpenDrawer(asset, 'remediation')}
                          className="px-2 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition-colors inline-flex items-center gap-1"
                          title="Generate GitHub Issue"
                        >
                          <GitPullRequest className="w-3 h-3" />
                          <span>Fix</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="px-5 py-3 border-t border-white/[0.06] flex items-center justify-between text-xs text-gray-400">
          <div>
            Page <span className="font-mono text-white font-semibold">{currentPage}</span> of{' '}
            <span className="font-mono text-white font-semibold">{totalPages}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1.5 rounded bg-white/[0.04] hover:bg-white/[0.08] disabled:opacity-30 disabled:cursor-not-allowed border border-white/10 text-gray-200"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1.5 rounded bg-white/[0.04] hover:bg-white/[0.08] disabled:opacity-30 disabled:cursor-not-allowed border border-white/10 text-gray-200"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Slide-Over Inspection Drawer */}
      {drawerAsset && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in">
          <div
            className="w-full max-w-2xl bg-navy-900 border-l border-white/10 shadow-2xl flex flex-col h-full overflow-hidden animate-slide-up"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Drawer Header */}
            <div className="p-6 border-b border-white/10 bg-navy-950/70 flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <PQCBadge status={drawerAsset.quantum_status || drawerAsset.pqc_status} size="sm" />
                  {getSensitivityBadge(drawerAsset.sensitivity)}
                </div>
                <h2 className="text-xl font-bold text-white font-mono">{drawerAsset.name}</h2>
                <p className="text-xs text-cyan-400 font-mono mt-0.5">
                  {drawerAsset.algorithm} • {drawerAsset.primitive} • {drawerAsset.source_type}
                </p>
              </div>
              <button
                onClick={() => setDrawerAsset(null)}
                className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-white/5 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Tab Navigation */}
            <div className="flex border-b border-white/10 bg-navy-950/40 px-6">
              {[
                { id: 'details', label: 'Technical Details', icon: FileCode },
                { id: 'ai', label: 'Quantum Attack Mechanics', icon: Sparkles },
                { id: 'remediation', label: 'GitHub Remediation', icon: GitPullRequest },
              ].map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => {
                    setDrawerTab(id);
                    if (id === 'ai' && !explanationData) loadExplanation(drawerAsset);
                    if (id === 'remediation' && !issueData) loadRemediation(drawerAsset);
                  }}
                  className={`flex items-center gap-2 py-3 px-4 border-b-2 text-xs font-semibold transition-all ${
                    drawerTab === id
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-gray-400 hover:text-gray-200'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{label}</span>
                </button>
              ))}
            </div>

            {/* Drawer Body */}
            <div className="flex-1 p-6 overflow-y-auto space-y-6 text-sm text-gray-300">
              {/* TAB 1: TECHNICAL DETAILS */}
              {drawerTab === 'details' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <DetailBox label="Algorithm Family" value={drawerAsset.algorithm_family || drawerAsset.algorithm} />
                    <DetailBox label="Key Length" value={drawerAsset.key_size ? `${drawerAsset.key_size} bits` : 'N/A'} />
                    <DetailBox label="Primitive Mode" value={drawerAsset.mode || 'Standard'} />
                    <DetailBox label="Library Dependency" value={drawerAsset.library || 'Native TLS / Standard'} />
                    <DetailBox label="Confidence" value={drawerAsset.confidence ? `${Math.round(drawerAsset.confidence * 100)}%` : '100%'} />
                    <DetailBox label="Risk Score" value={`${drawerAsset.risk_score || 0} / 100`} />
                  </div>

                  {/* Code Line Match / AST Evidence */}
                  {drawerAsset.evidence?.code_line && (
                    <div className="rounded-xl border border-white/10 bg-navy-950 p-4 space-y-2">
                      <div className="flex items-center justify-between text-xs text-gray-400">
                        <span className="flex items-center gap-1.5 font-mono">
                          <Code2 className="w-3.5 h-3.5 text-cyan-400" />
                          AST Code Match ({drawerAsset.file_path}:{drawerAsset.line_number})
                        </span>
                        <button
                          onClick={() => copyToClipboard(drawerAsset.evidence.code_line, 'code_line')}
                          className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          {copiedKey === 'code_line' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          <span>Copy</span>
                        </button>
                      </div>
                      <pre className="p-3 rounded-lg bg-black/60 font-mono text-xs text-cyan-300 overflow-x-auto border border-white/5">
                        {drawerAsset.evidence.code_line}
                      </pre>
                      {drawerAsset.function_name && (
                        <p className="text-[11px] text-gray-400 font-mono">
                          Function scope: <span className="text-gray-300">{drawerAsset.function_name}()</span>
                        </p>
                      )}
                    </div>
                  )}

                  {/* Vulnerability Summary */}
                  {drawerAsset.vulnerabilities?.length > 0 && (
                    <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-4 space-y-2">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-rose-400">
                        <ShieldAlert className="w-4 h-4" />
                        <span>Identified Cryptographic Vulnerabilities</span>
                      </div>
                      <ul className="list-disc list-inside text-xs text-gray-300 space-y-1">
                        {drawerAsset.vulnerabilities.map((v, i) => (
                          <li key={i}>{v}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: AI QUANTUM ATTACK MECHANICS */}
              {drawerTab === 'ai' && (
                <div className="space-y-4">
                  {isExplaining ? (
                    <div className="p-12 text-center text-gray-400">
                      <div className="animate-spin inline-block w-6 h-6 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full mb-3" />
                      <p className="text-xs">Computing Shor/Grover qubit dynamics and theoretical break timeline...</p>
                    </div>
                  ) : explanationData ? (
                    <>
                      <div className="p-4 rounded-xl bg-navy-950 border border-cyan-500/30">
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-1">
                          Vulnerability Synopsis
                        </h4>
                        <p className="text-xs text-gray-200 leading-relaxed">
                          {explanationData.quantum_vulnerability_summary}
                        </p>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div className="p-3.5 rounded-xl bg-navy-950/60 border border-white/5 space-y-1 text-xs">
                          <span className="text-gray-400 text-[11px] uppercase font-semibold">Attack Algorithm</span>
                          <p className="font-bold text-rose-400 font-mono">
                            {explanationData.theoretical_foundation?.attack_algorithm || 'Shor’s Algorithm'}
                          </p>
                        </div>
                        <div className="p-3.5 rounded-xl bg-navy-950/60 border border-white/5 space-y-1 text-xs">
                          <span className="text-gray-400 text-[11px] uppercase font-semibold">Qubits Required</span>
                          <p className="font-bold text-amber-400 font-mono">
                            {explanationData.theoretical_foundation?.qubits_required_estimate || '~4,098 logical'}
                          </p>
                        </div>
                      </div>

                      <div className="p-4 rounded-xl bg-navy-950/60 border border-white/5 space-y-2 text-xs">
                        <h4 className="font-semibold text-gray-300">Harvest Now, Decrypt Later (HNDL) Threat</h4>
                        <p className="text-gray-400 leading-relaxed">
                          {explanationData.harvest_now_decrypt_later_risk?.threat_description}
                        </p>
                      </div>

                      {/* Tailored Replacement Snippet */}
                      {explanationData.tailored_remediation && (
                        <div className="p-4 rounded-xl bg-navy-950 border border-emerald-500/30 space-y-2">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-semibold text-emerald-400">
                              Drop-in Replacement: {explanationData.tailored_remediation.recommended_replacement}
                            </span>
                            <button
                              onClick={() => copyToClipboard(explanationData.tailored_remediation.code_snippet, 'remed_snippet')}
                              className="text-[11px] text-emerald-400 hover:underline flex items-center gap-1"
                            >
                              {copiedKey === 'remed_snippet' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                              <span>Copy Code</span>
                            </button>
                          </div>
                          <pre className="p-3 rounded-lg bg-black/60 font-mono text-xs text-emerald-300 overflow-x-auto border border-emerald-500/20">
                            {explanationData.tailored_remediation.code_snippet}
                          </pre>
                        </div>
                      )}
                    </>
                  ) : null}
                </div>
              )}

              {/* TAB 3: GITHUB REMEDIATION */}
              {drawerTab === 'remediation' && (
                <div className="space-y-4">
                  {isLoadingIssue ? (
                    <div className="p-12 text-center text-gray-400">
                      <div className="animate-spin inline-block w-6 h-6 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full mb-3" />
                      <p className="text-xs">Generating engineering remediation specifications...</p>
                    </div>
                  ) : issueData ? (
                    <>
                      <div>
                        <label className="block text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">
                          Issue Title
                        </label>
                        <input
                          type="text"
                          readOnly
                          value={issueData.title}
                          className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-white/10 font-mono text-xs text-white"
                        />
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-1 text-xs">
                          <label className="font-semibold text-gray-400 uppercase tracking-wider text-[11px]">
                            Issue Markdown Body
                          </label>
                          <button
                            onClick={() => copyToClipboard(issueData.body, 'issue_body')}
                            className="text-cyan-400 hover:underline flex items-center gap-1"
                          >
                            {copiedKey === 'issue_body' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                            <span>Copy Markdown</span>
                          </button>
                        </div>
                        <textarea
                          rows={6}
                          readOnly
                          value={issueData.body}
                          className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-white/10 font-mono text-xs text-gray-300"
                        />
                      </div>

                      {/* Remote Publisher */}
                      <form onSubmit={handlePublishIssue} className="p-4 rounded-xl bg-navy-950 border border-white/10 space-y-3">
                        <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                          1-Click Remote GitHub Publishing
                        </h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                          <div>
                            <label className="block text-gray-400 mb-1">Owner / Org</label>
                            <input
                              type="text"
                              placeholder="e.g. acme-corp"
                              value={repoOwner}
                              onChange={(e) => setRepoOwner(e.target.value)}
                              className="w-full px-3 py-1.5 rounded bg-navy-900 border border-white/10 text-white"
                            />
                          </div>
                          <div>
                            <label className="block text-gray-400 mb-1">Repository Name</label>
                            <input
                              type="text"
                              placeholder="e.g. auth-service"
                              value={repoName}
                              onChange={(e) => setRepoName(e.target.value)}
                              className="w-full px-3 py-1.5 rounded bg-navy-900 border border-white/10 text-white"
                            />
                          </div>
                          <div className="sm:col-span-2">
                            <label className="block text-gray-400 mb-1">GitHub Personal Access Token</label>
                            <input
                              type="password"
                              placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                              value={githubToken}
                              onChange={(e) => setGithubToken(e.target.value)}
                              className="w-full px-3 py-1.5 rounded bg-navy-900 border border-white/10 text-white font-mono"
                            />
                          </div>
                        </div>
                        <div className="flex justify-end pt-1">
                          <button
                            type="submit"
                            disabled={isPublishing}
                            className="btn-primary text-xs py-2 px-4 inline-flex items-center gap-1.5"
                          >
                            <Send className="w-3.5 h-3.5" />
                            <span>{isPublishing ? 'Publishing Issue...' : 'Publish to GitHub'}</span>
                          </button>
                        </div>
                      </form>
                    </>
                  ) : null}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailBox({ label, value }) {
  return (
    <div className="p-3 rounded-lg bg-navy-950/70 border border-white/5">
      <div className="text-[10px] text-gray-500 uppercase font-semibold tracking-wider">{label}</div>
      <div className="text-xs font-bold text-gray-200 mt-0.5 truncate font-mono">{value}</div>
    </div>
  );
}

function SortIcon({ field, currentField, order }) {
  if (field !== currentField) {
    return <ArrowUpDown className="w-3 h-3 text-gray-500 opacity-40 group-hover:opacity-100 transition-opacity" />;
  }
  return order === 'asc' ? (
    <ArrowUp className="w-3 h-3 text-cyan-400" />
  ) : (
    <ArrowDown className="w-3 h-3 text-cyan-400" />
  );
}
