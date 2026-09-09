import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { getCryptoAssets, explainFinding, getIssuePreview, publishGitHubIssue } from '../api/client';

export default function CryptoInventory() {
  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [primitiveFilter, setPrimitiveFilter] = useState('');
  const [sensitivityFilter, setSensitivityFilter] = useState('');

  // Modals state
  const [activeExplainAsset, setActiveExplainAsset] = useState(null);
  const [explanationData, setExplanationData] = useState(null);
  const [isExplaining, setIsExplaining] = useState(false);

  const [activeRemediationAsset, setActiveRemediationAsset] = useState(null);
  const [issueData, setIssueData] = useState(null);
  const [isLoadingIssue, setIsLoadingIssue] = useState(false);
  const [repoOwner, setRepoOwner] = useState('');
  const [repoName, setRepoName] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [isPublishing, setIsPublishing] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['crypto-assets', sourceFilter, statusFilter, primitiveFilter],
    queryFn: () =>
      getCryptoAssets({
        limit: 100,
        source_type: sourceFilter || undefined,
        pqc_status: statusFilter || undefined,
        primitive: primitiveFilter || undefined,
      }),
  });

  const assets = data?.items || [];

  const filteredAssets = assets.filter((item) => {
    if (searchTerm) {
      const match =
        item.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.algorithm?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.file_path?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.hostname?.toLowerCase().includes(searchTerm.toLowerCase());
      if (!match) return false;
    }
    if (sensitivityFilter && (item.sensitivity || 'general').toLowerCase() !== sensitivityFilter.toLowerCase()) {
      return false;
    }
    return true;
  });

  const handleOpenExplain = async (asset) => {
    setActiveExplainAsset(asset);
    setIsExplaining(true);
    try {
      const res = await explainFinding({ finding_id: asset.id });
      setExplanationData(res);
    } catch (err) {
      toast.error('Failed to load AI explanation');
    } finally {
      setIsExplaining(false);
    }
  };

  const handleOpenRemediation = async (asset) => {
    setActiveRemediationAsset(asset);
    setIsLoadingIssue(true);
    try {
      const res = await getIssuePreview(asset.id);
      setIssueData(res);
    } catch (err) {
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
        toast.success(`Issue published: ${res.issue_url}`);
        setActiveRemediationAsset(null);
      } else {
        toast.error(res.message || 'Publishing failed');
      }
    } catch (err) {
      toast.error('Failed to publish GitHub Issue');
    } finally {
      setIsPublishing(false);
    }
  };

  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard!`);
  };

  const getStatusBadge = (status) => {
    const s = (status || '').toUpperCase();
    if (s.includes('SAFE')) {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">Safe</span>;
    }
    if (s.includes('HYBRID') || s.includes('MARGIN') || s.includes('REDUCED')) {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">Reduced Margin</span>;
    }
    return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30">Vulnerable</span>;
  };

  const getSensitivityBadge = (sens) => {
    const s = (sens || 'general').toLowerCase();
    if (s === 'financial' || s === 'government_id') {
      return <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/30">{s}</span>;
    }
    if (s === 'authentication' || s === 'medical' || s === 'pii') {
      return <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-blue-500/10 text-blue-400 border border-blue-500/30">{s}</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-gray-500/10 text-gray-400 border border-gray-500/20">{s}</span>;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <span>📦</span> Canonical Cryptographic Inventory
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Normalized catalog of all cryptographic primitives, keys, certificates, and algorithms across source code, containers, binaries, and networks.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => refetch()}
            className="px-4 py-2 rounded-lg text-xs font-medium bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 transition-colors"
          >
            ↻ Refresh
          </button>
          <Link
            to="/scan/new"
            className="px-4 py-2 rounded-lg text-xs font-medium bg-cyan-500 hover:bg-cyan-400 text-black font-semibold transition-colors shadow-glow-cyan"
          >
            + Run New Scan
          </Link>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="glass-card p-4 grid grid-cols-1 md:grid-cols-5 gap-3">
        <div>
          <label className="block text-[11px] uppercase tracking-wider text-gray-400 mb-1">Search</label>
          <input
            type="text"
            placeholder="Search name, algo, file..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg bg-navy-800/80 border border-white/10 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-400/50"
          />
        </div>
        <div>
          <label className="block text-[11px] uppercase tracking-wider text-gray-400 mb-1">Source Type</label>
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg bg-navy-800/80 border border-white/10 text-sm text-gray-200 focus:outline-none focus:border-cyan-400/50"
          >
            <option value="">All Sources</option>
            <option value="source_code">Source Code</option>
            <option value="container">Container Image</option>
            <option value="binary">Compiled Binary</option>
            <option value="network">Network / TLS</option>
          </select>
        </div>
        <div>
          <label className="block text-[11px] uppercase tracking-wider text-gray-400 mb-1">Quantum Status</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg bg-navy-800/80 border border-white/10 text-sm text-gray-200 focus:outline-none focus:border-cyan-400/50"
          >
            <option value="">All Statuses</option>
            <option value="VULNERABLE">Vulnerable</option>
            <option value="HYBRID_READY">Reduced / Hybrid</option>
            <option value="QUANTUM_SAFE">Quantum Safe</option>
          </select>
        </div>
        <div>
          <label className="block text-[11px] uppercase tracking-wider text-gray-400 mb-1">Primitive</label>
          <select
            value={primitiveFilter}
            onChange={(e) => setPrimitiveFilter(e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg bg-navy-800/80 border border-white/10 text-sm text-gray-200 focus:outline-none focus:border-cyan-400/50"
          >
            <option value="">All Primitives</option>
            <option value="asymmetric">Asymmetric</option>
            <option value="symmetric">Symmetric</option>
            <option value="hash">Hash / Digest</option>
            <option value="mac">MAC / KDF</option>
            <option value="pqc">Post-Quantum</option>
          </select>
        </div>
        <div>
          <label className="block text-[11px] uppercase tracking-wider text-gray-400 mb-1">Sensitivity</label>
          <select
            value={sensitivityFilter}
            onChange={(e) => setSensitivityFilter(e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg bg-navy-800/80 border border-white/10 text-sm text-gray-200 focus:outline-none focus:border-cyan-400/50"
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

      {/* Inventory Table */}
      <div className="glass-card overflow-hidden border border-white/5">
        <div className="p-4 border-b border-white/5 flex items-center justify-between">
          <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
            Showing {filteredAssets.length} of {assets.length} Findings
          </span>
        </div>

        {isLoading ? (
          <div className="p-12 text-center text-gray-400">Loading cryptographic inventory...</div>
        ) : filteredAssets.length === 0 ? (
          <div className="p-12 text-center text-gray-500">No cryptographic findings match the selected filters.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/5 bg-white/[0.02] text-[11px] uppercase tracking-wider text-gray-400 font-semibold">
                  <th className="py-3 px-4">Finding Name</th>
                  <th className="py-3 px-4">Algorithm & Key</th>
                  <th className="py-3 px-4">Primitive</th>
                  <th className="py-3 px-4">Source & Provenance</th>
                  <th className="py-3 px-4">Sensitivity</th>
                  <th className="py-3 px-4">Quantum Status</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-sm">
                {filteredAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-white/[0.03] transition-colors group">
                    <td className="py-3 px-4">
                      <div className="font-medium text-white group-hover:text-cyan-400 transition-colors">
                        {asset.name}
                      </div>
                      {asset.usage && <div className="text-[11px] text-gray-500">Usage: {asset.usage}</div>}
                    </td>
                    <td className="py-3 px-4">
                      <span className="font-mono font-semibold text-cyan-300">
                        {asset.algorithm || 'N/A'}
                      </span>
                      {asset.key_size && (
                        <span className="ml-1 text-xs text-gray-400">({asset.key_size} bit)</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs text-gray-300 capitalize">
                      {asset.primitive || 'standard'}
                    </td>
                    <td className="py-3 px-4 text-xs">
                      <div className="text-gray-300 capitalize font-medium">{asset.source_type}</div>
                      <div className="text-gray-500 font-mono text-[11px] truncate max-w-xs" title={asset.file_path || asset.hostname}>
                        {asset.file_path ? `${asset.file_path}${asset.line_number ? `:${asset.line_number}` : ''}` : asset.hostname || '—'}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      {getSensitivityBadge(asset.sensitivity)}
                    </td>
                    <td className="py-3 px-4">
                      {getStatusBadge(asset.quantum_status || asset.pqc_status)}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-12 bg-gray-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              (asset.risk_score || 0) > 70
                                ? 'bg-red-500'
                                : (asset.risk_score || 0) > 40
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, asset.risk_score || 0)}%` }}
                          />
                        </div>
                        <span className="font-mono text-xs text-gray-300">
                          {asset.risk_score != null ? Math.round(asset.risk_score) : '—'}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      <button
                        onClick={() => handleOpenExplain(asset)}
                        className="px-2.5 py-1 rounded text-xs font-medium bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 transition-colors"
                        title="AI Quantum Explanation"
                      >
                        🤖 Explain
                      </button>
                      <button
                        onClick={() => handleOpenRemediation(asset)}
                        className="px-2.5 py-1 rounded text-xs font-medium bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition-colors"
                        title="Remediate & Export Issue"
                      >
                        ⚡ Remediate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* AI Explanation Modal */}
      {activeExplainAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="glass-card max-w-3xl w-full max-h-[90vh] overflow-y-auto p-6 border border-cyan-500/30 shadow-2xl relative">
            <button
              onClick={() => {
                setActiveExplainAsset(null);
                setExplanationData(null);
              }}
              className="absolute top-4 right-4 text-gray-400 hover:text-white text-xl"
            >
              ✕
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-xl">
                🤖
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">
                  Quantum Vulnerability Deep-Dive: {activeExplainAsset.name}
                </h2>
                <p className="text-xs text-cyan-400 font-mono">
                  {activeExplainAsset.algorithm} • {activeExplainAsset.primitive || 'asymmetric'}
                </p>
              </div>
            </div>

            {isExplaining ? (
              <div className="p-12 text-center text-gray-400">
                <div className="animate-spin inline-block w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mb-3" />
                <p>Computing Shor/Grover analysis and FIPS 203/204 remediation...</p>
              </div>
            ) : explanationData ? (
              <div className="space-y-4 text-sm text-gray-300">
                {/* Summary */}
                <div className="p-4 rounded-xl bg-navy-950/80 border border-cyan-500/20">
                  <h3 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-1">
                    Vulnerability Synopsis
                  </h3>
                  <p className="text-gray-200 leading-relaxed">
                    {explanationData.quantum_vulnerability_summary}
                  </p>
                </div>

                {/* Mathematical Theory & Qubit requirements */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="p-4 rounded-xl bg-navy-950/60 border border-white/5">
                    <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                      Theoretical Attack Mechanics
                    </h3>
                    <div className="space-y-1 text-xs">
                      <div><span className="text-gray-500">Attack Algorithm:</span> <span className="text-red-400 font-medium">{explanationData.theoretical_foundation?.attack_algorithm}</span></div>
                      <div><span className="text-gray-500">Complexity:</span> <span className="text-amber-300 font-mono">{explanationData.theoretical_foundation?.quantum_complexity}</span></div>
                      <div><span className="text-gray-500">Estimated Qubits:</span> <span className="text-purple-300 font-mono">{explanationData.theoretical_foundation?.qubits_required_estimate}</span></div>
                    </div>
                    <p className="text-xs text-gray-400 mt-2">
                      {explanationData.theoretical_foundation?.mathematical_basis}
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-navy-950/60 border border-white/5">
                    <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                      Harvest Now Decrypt Later (HNDL) Risk
                    </h3>
                    <div className="text-xs mb-2">
                      <span className="text-gray-500">Exposure Level: </span>
                      <span className="font-bold text-red-400">
                        {explanationData.harvest_now_decrypt_later_risk?.hndl_exposure}
                      </span>
                    </div>
                    <p className="text-xs text-gray-300 mb-2">
                      {explanationData.harvest_now_decrypt_later_risk?.threat_description}
                    </p>
                    <div className="text-[11px] text-gray-400">
                      <strong>Impact:</strong> {explanationData.harvest_now_decrypt_later_risk?.confidentiality_impact}
                    </div>
                  </div>
                </div>

                {/* Regulatory Timelines */}
                <div className="p-4 rounded-xl bg-navy-950/60 border border-white/5">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                    Regulatory Deadlines
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-cyan-400 font-semibold">NSA CNSA 2.0: </span>
                      <span className="text-gray-300">{explanationData.regulatory_implications?.cnsa_deadline}</span>
                    </div>
                    <div>
                      <span className="text-cyan-400 font-semibold">NIST FIPS Standard: </span>
                      <span className="text-gray-300">{explanationData.regulatory_implications?.nist_standard}</span>
                    </div>
                  </div>
                </div>

                {/* Remediation Code */}
                {explanationData.tailored_remediation && (
                  <div className="p-4 rounded-xl bg-navy-950/80 border border-emerald-500/20">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                        Tailored Post-Quantum Remediation ({explanationData.tailored_remediation.recommended_replacement})
                      </h3>
                      <button
                        onClick={() => copyToClipboard(explanationData.tailored_remediation.code_snippet, 'Remediation code')}
                        className="text-xs text-emerald-400 hover:text-emerald-300 underline"
                      >
                        Copy Code
                      </button>
                    </div>
                    <pre className="p-3 rounded bg-black/60 font-mono text-xs text-emerald-300 overflow-x-auto">
                      {explanationData.tailored_remediation.code_snippet}
                    </pre>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* GitHub Remediation Modal */}
      {activeRemediationAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="glass-card max-w-3xl w-full max-h-[90vh] overflow-y-auto p-6 border border-emerald-500/30 shadow-2xl relative">
            <button
              onClick={() => {
                setActiveRemediationAsset(null);
                setIssueData(null);
              }}
              className="absolute top-4 right-4 text-gray-400 hover:text-white text-xl"
            >
              ✕
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-xl">
                🐙
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">
                  Developer Remediation & GitHub Issue
                </h2>
                <p className="text-xs text-emerald-400">
                  Target: {activeRemediationAsset.name} ({activeRemediationAsset.algorithm})
                </p>
              </div>
            </div>

            {isLoadingIssue ? (
              <div className="p-12 text-center text-gray-400">
                <div className="animate-spin inline-block w-8 h-8 border-2 border-emerald-400 border-t-transparent rounded-full mb-3" />
                <p>Generating GitHub issue markdown...</p>
              </div>
            ) : issueData ? (
              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Issue Title</label>
                    <button
                      onClick={() => copyToClipboard(issueData.title, 'Title')}
                      className="text-xs text-cyan-400 hover:underline"
                    >
                      Copy Title
                    </button>
                  </div>
                  <input
                    type="text"
                    readOnly
                    value={issueData.title}
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-white/10 font-mono text-xs text-white"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Issue Body (Markdown)</label>
                    <button
                      onClick={() => copyToClipboard(issueData.body, 'Issue Markdown')}
                      className="text-xs text-cyan-400 hover:underline"
                    >
                      Copy Markdown
                    </button>
                  </div>
                  <textarea
                    rows={8}
                    readOnly
                    value={issueData.body}
                    className="w-full px-3 py-2 rounded-lg bg-navy-950 border border-white/10 font-mono text-xs text-gray-300"
                  />
                </div>

                {/* Remote GitHub Publisher */}
                <form onSubmit={handlePublishIssue} className="p-4 rounded-xl bg-navy-950/80 border border-white/10 space-y-3">
                  <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
                    Publish Directly to Remote GitHub Repository
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div>
                      <label className="block text-[11px] text-gray-400 mb-1">Owner / Org</label>
                      <input
                        type="text"
                        placeholder="e.g. acme-corp"
                        value={repoOwner}
                        onChange={(e) => setRepoOwner(e.target.value)}
                        className="w-full px-3 py-1.5 rounded bg-navy-900 border border-white/10 text-xs text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] text-gray-400 mb-1">Repository Name</label>
                      <input
                        type="text"
                        placeholder="e.g. backend-service"
                        value={repoName}
                        onChange={(e) => setRepoName(e.target.value)}
                        className="w-full px-3 py-1.5 rounded bg-navy-900 border border-white/10 text-xs text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] text-gray-400 mb-1">Personal Access Token</label>
                      <input
                        type="password"
                        placeholder="ghp_xxxxxxxxxxxx"
                        value={githubToken}
                        onChange={(e) => setGithubToken(e.target.value)}
                        className="w-full px-3 py-1.5 rounded bg-navy-900 border border-white/10 text-xs text-white"
                      />
                    </div>
                  </div>
                  <div className="flex justify-end pt-2">
                    <button
                      type="submit"
                      disabled={isPublishing}
                      className="px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-black transition-colors disabled:opacity-50"
                    >
                      {isPublishing ? 'Publishing...' : '🚀 Create GitHub Issue'}
                    </button>
                  </div>
                </form>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
