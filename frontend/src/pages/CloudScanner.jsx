import React, { useState, useEffect } from 'react';
import {
  Cloud,
  Server,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Zap,
  Terminal,
  Copy,
  Check,
  DollarSign,
  Cpu,
  Layers,
  Search,
  ExternalLink,
  ArrowRight,
  Sliders,
  Filter,
} from 'lucide-react';
import toast from 'react-hot-toast';
import {
  scanCloudFleet,
  getCloudInstanceCatalog,
  evaluateCloudInventory,
} from '../api/client';

export default function CloudScanner() {
  const [provider, setProvider] = useState('AWS');
  const [roleArn, setRoleArn] = useState('arn:aws:iam::123456789012:role/CypherCitePqcAudit');
  const [externalId, setExternalId] = useState('cc-audit-7890');
  const [region, setRegion] = useState('us-east-1');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [copiedKey, setCopiedKey] = useState(null);
  const [catalog, setCatalog] = useState(null);
  const [activeTab, setActiveTab] = useState('fleet'); // 'fleet' | 'catalog' | 'terraform'

  const runAudit = async (useDemo = true) => {
    setLoading(true);
    try {
      const res = await scanCloudFleet(provider, {
        provider,
        role_arn: roleArn,
        external_id: externalId,
        region,
        use_demo_fleet: useDemo,
      });
      setReport(res.report);
      toast.success(`${provider} cloud fleet audit completed!`);
    } catch (err) {
      console.error('Failed to audit cloud fleet:', err);
      toast.error(`Failed to audit ${provider} cloud fleet`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Initial audit with default provider
    runAudit(true);

    // Fetch catalog
    getCloudInstanceCatalog().then((res) => {
      setCatalog(res);
    }).catch((err) => console.error(err));
  }, [provider]);

  const copySnippet = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    toast.success('Remediation snippet copied!');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'PQC_READY':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 inline-flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            PQC READY
          </span>
        );
      case 'UPGRADE_RECOMMENDED':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 inline-flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            UPGRADE RECOMMENDED
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 inline-flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            UPGRADE REQUIRED
          </span>
        );
    }
  };

  const filteredAssets = (report?.assets || []).filter((a) => {
    if (statusFilter === 'ALL') return true;
    return a.pqc_status === statusFilter;
  });

  return (
    <div className="space-y-7 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20 font-mono">
              AGENTLESS CLOUD SCANNER
            </span>
            <span className="text-xs text-gray-400 font-mono">PQC-CSPM • AWS / AZURE / GCP</span>
          </div>
          <h1 className="page-header flex items-center gap-3">
            <Cloud className="w-6 h-6 text-cyan-400" />
            <span>Cloud Infrastructure PQC Scanner</span>
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Audit cloud compute shapes, CPU silicon (AVX-512 / Graviton SVE), CloudHSMs, and Load Balancer TLS policies.
          </p>
        </div>

        {/* Provider Toggle */}
        <div className="flex items-center bg-navy-900 border border-white/10 rounded-xl p-1">
          {['AWS', 'Azure', 'GCP'].map((p) => (
            <button
              key={p}
              onClick={() => setProvider(p)}
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
                provider === p
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 shadow-glow-cyan/20'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* IAM Role Connection Bar */}
      <div className="rounded-xl border border-white/10 bg-navy-900/70 p-4 backdrop-blur-xl flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex flex-col sm:flex-row sm:items-center gap-3 flex-1 text-xs">
          <div className="flex-1">
            <label className="block text-gray-400 mb-1 font-mono">
              {provider === 'AWS' ? 'Read-Only IAM Role ARN' : provider === 'Azure' ? 'Azure Reader Principal' : 'GCP Service Account'}
            </label>
            <input
              type="text"
              value={roleArn}
              onChange={(e) => setRoleArn(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-navy-950 border border-white/10 text-white font-mono focus:outline-none focus:border-cyan-400/50"
            />
          </div>

          <div className="w-full sm:w-44">
            <label className="block text-gray-400 mb-1 font-mono">External ID / Tenant</label>
            <input
              type="text"
              value={externalId}
              onChange={(e) => setExternalId(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-navy-950 border border-white/10 text-white font-mono focus:outline-none focus:border-cyan-400/50"
            />
          </div>

          <div className="w-full sm:w-36">
            <label className="block text-gray-400 mb-1 font-mono">Region</label>
            <input
              type="text"
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-navy-950 border border-white/10 text-white font-mono focus:outline-none focus:border-cyan-400/50"
            />
          </div>
        </div>

        <div className="flex items-center gap-2.5 pt-2 lg:pt-0">
          <button
            onClick={() => runAudit(true)}
            disabled={loading}
            className="btn-primary text-xs py-2 px-4 flex items-center gap-2 whitespace-nowrap"
          >
            {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
            <span>Run Fleet Audit</span>
          </button>
        </div>
      </div>

      {/* KPI Metrics */}
      {report && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="stat-card">
            <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">Fleet PQC Score</div>
            <div className="text-2xl font-bold text-cyan-400 font-mono mt-1">
              {report.fleet_pqc_score}
              <span className="text-xs text-gray-500 font-sans">/100</span>
            </div>
            <div className="text-[10px] text-gray-500 mt-1">{report.total_assets} cloud assets audited</div>
          </div>

          <div className="stat-card">
            <div className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider">PQC Ready</div>
            <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">{report.pqc_ready_count}</div>
            <div className="text-[10px] text-gray-500 mt-1">AVX-512 / Graviton SVE</div>
          </div>

          <div className="stat-card">
            <div className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider">Upgrade Rec.</div>
            <div className="text-2xl font-bold text-amber-400 font-mono mt-1">{report.upgrade_recommended_count}</div>
            <div className="text-[10px] text-gray-500 mt-1">Burstable CPU / Suboptimal</div>
          </div>

          <div className="stat-card">
            <div className="text-[11px] font-semibold text-rose-400 uppercase tracking-wider">Upgrade Required</div>
            <div className="text-2xl font-bold text-rose-400 font-mono mt-1">{report.upgrade_required_count}</div>
            <div className="text-[10px] text-gray-500 mt-1">Legacy Silicon / CloudHSM</div>
          </div>

          <div className="stat-card">
            <div className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider">Potential Savings</div>
            <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">
              ${report.potential_monthly_savings_usd}
              <span className="text-xs text-gray-500 font-sans">/mo</span>
            </div>
            <div className="text-[10px] text-gray-500 mt-1">via ARM Graviton migration</div>
          </div>
        </div>
      )}

      {/* Main View Tabs */}
      <div className="flex border-b border-white/10 gap-6 text-xs font-semibold">
        <button
          onClick={() => setActiveTab('fleet')}
          className={`pb-3 border-b-2 transition-all flex items-center gap-2 ${
            activeTab === 'fleet'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          <Server className="w-4 h-4" />
          <span>Audited Cloud Fleet ({report?.assets?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('terraform')}
          className={`pb-3 border-b-2 transition-all flex items-center gap-2 ${
            activeTab === 'terraform'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>Terraform & CLI Modernization Blueprint</span>
        </button>

        <button
          onClick={() => setActiveTab('catalog')}
          className={`pb-3 border-b-2 transition-all flex items-center gap-2 ${
            activeTab === 'catalog'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>Cloud Silicon PQC Knowledge Matrix</span>
        </button>
      </div>

      {/* TAB 1: FLEET INVENTORY */}
      {activeTab === 'fleet' && report && (
        <div className="space-y-4">
          {/* Status Filters */}
          <div className="flex items-center gap-2 text-xs">
            <span className="text-gray-400 flex items-center gap-1">
              <Filter className="w-3.5 h-3.5" />
              Filter:
            </span>
            {['ALL', 'PQC_READY', 'UPGRADE_RECOMMENDED', 'UPGRADE_REQUIRED'].map((f) => (
              <button
                key={f}
                onClick={() => setStatusFilter(f)}
                className={`px-2.5 py-1 rounded-lg font-mono text-[11px] transition-all ${
                  statusFilter === f
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30'
                    : 'bg-navy-900 text-gray-400 border border-white/5 hover:border-white/15'
                }`}
              >
                {f}
              </button>
            ))}
          </div>

          {/* Table */}
          <div className="rounded-xl border border-white/10 bg-navy-900/60 overflow-hidden backdrop-blur-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-white/[0.02] border-b border-white/10 text-gray-400 font-mono uppercase text-[10px]">
                  <tr>
                    <th className="p-3.5">Asset / Name</th>
                    <th className="p-3.5">Service Type</th>
                    <th className="p-3.5">Shape / Model</th>
                    <th className="p-3.5">CPU Silicon & Vector</th>
                    <th className="p-3.5">PQC Status</th>
                    <th className="p-3.5">Upgrade Target</th>
                    <th className="p-3.5">Cost Impact</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filteredAssets.map((asset) => (
                    <tr key={asset.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="p-3.5">
                        <div className="font-semibold text-white">{asset.name}</div>
                        <div className="text-[10px] text-gray-500 font-mono">{asset.id} • {asset.region}</div>
                      </td>
                      <td className="p-3.5">
                        <span className="px-2 py-0.5 rounded bg-white/5 text-gray-300 font-mono text-[10px]">
                          {asset.service_type}
                        </span>
                      </td>
                      <td className="p-3.5 font-mono text-cyan-300">{asset.instance_type_or_model}</td>
                      <td className="p-3.5">
                        <div className="text-gray-300">{asset.cpu_family}</div>
                        <div className="flex gap-1.5 mt-0.5 font-mono text-[9px]">
                          {asset.avx512_supported && (
                            <span className="text-emerald-400 bg-emerald-500/10 px-1 rounded">AVX-512</span>
                          )}
                          {asset.neon_supported && (
                            <span className="text-emerald-400 bg-emerald-500/10 px-1 rounded">ARM NEON</span>
                          )}
                          {asset.performance_multiplier > 1.5 && (
                            <span className="text-rose-400 bg-rose-500/10 px-1 rounded">
                              {asset.performance_multiplier}x Slowdown
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-3.5">{getStatusBadge(asset.pqc_status)}</td>
                      <td className="p-3.5">
                        {asset.upgrade_target ? (
                          <div className="flex items-center gap-1.5 text-cyan-300 font-mono font-semibold">
                            <span>{asset.upgrade_target}</span>
                          </div>
                        ) : (
                          <span className="text-gray-500">—</span>
                        )}
                        <div className="text-[10px] text-gray-400 line-clamp-1 mt-0.5">{asset.recommendation}</div>
                      </td>
                      <td className="p-3.5">
                        <div className="font-mono text-white">${asset.estimated_monthly_cost_usd}/mo</div>
                        {asset.potential_savings_pct > 0 && (
                          <div className="text-[10px] text-emerald-400 font-mono">
                            -{asset.potential_savings_pct}% with Graviton
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: TERRAFORM BLUEPRINT */}
      {activeTab === 'terraform' && report && (
        <div className="space-y-6">
          <div className="rounded-xl border border-white/10 bg-navy-900/60 p-5 backdrop-blur-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-cyan-400">
                <Terminal className="w-4 h-4" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Automated Terraform Upgrade Plan
                </h3>
              </div>
              <button
                onClick={() => copySnippet(report.remediation_terraform, 'tf')}
                className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
              >
                {copiedKey === 'tf' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === 'tf' ? 'Copied' : 'Copy Terraform'}</span>
              </button>
            </div>
            <pre className="p-4 rounded-lg bg-navy-950 border border-white/10 text-xs font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {report.remediation_terraform}
            </pre>
          </div>

          <div className="rounded-xl border border-white/10 bg-navy-900/60 p-5 backdrop-blur-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-cyan-400">
                <Terminal className="w-4 h-4" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  AWS CLI Remediation Commands
                </h3>
              </div>
              <button
                onClick={() => copySnippet(report.remediation_cli, 'cli')}
                className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
              >
                {copiedKey === 'cli' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === 'cli' ? 'Copied' : 'Copy CLI'}</span>
              </button>
            </div>
            <pre className="p-4 rounded-lg bg-navy-950 border border-white/10 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {report.remediation_cli}
            </pre>
          </div>
        </div>
      )}

      {/* TAB 3: SILICON KNOWLEDGE MATRIX */}
      {activeTab === 'catalog' && catalog && (
        <div className="rounded-xl border border-white/10 bg-navy-900/60 p-5 backdrop-blur-xl space-y-4">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>Cloud Silicon & Processor Capability Reference</span>
          </h3>
          <p className="text-xs text-gray-400">
            Authoritative mapping of cloud VM shapes to physical processor architecture, vector extensions, and PQC status:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pt-2">
            {Object.entries(catalog.compute_shapes).map(([shape, details]) => (
              <div key={shape} className="p-4 rounded-lg border border-white/10 bg-navy-950/70 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold font-mono text-cyan-300">{shape}</span>
                  {getStatusBadge(details.pqc_status)}
                </div>
                <div className="text-xs text-white font-medium">{details.cpu_family}</div>
                <div className="text-[11px] text-gray-400 leading-snug">{details.recommendation}</div>
                <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-gray-500 font-mono">
                  <span>Provider: {details.provider}</span>
                  <span>AVX-512: {details.avx512 ? '✓' : '✗'} • NEON: {details.neon ? '✓' : '✗'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
