import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  FileText,
  FileSpreadsheet,
  Download,
  Copy,
  Table,
  ArrowLeft,
  Check,
  Layers,
} from 'lucide-react';
import { useCBOM } from '../hooks/useScanResults';
import { downloadCBOM } from '../api/client';
import toast from 'react-hot-toast';

export default function CBOMReport() {
  const { scanId } = useParams();
  const { data: cbom, isLoading } = useCBOM(scanId);
  const [viewMode, setViewMode] = useState('json'); // json, table

  const handleDownload = async (format) => {
    try {
      await downloadCBOM(scanId, format);
      toast.success(`Downloaded ${format.toUpperCase()} file`);
    } catch {
      toast.error('Download failed');
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500 animate-pulse">Loading CBOM...</div>
      </div>
    );
  }

  if (!cbom) {
    return (
      <div className="text-center py-16">
        <p className="text-gray-500 text-lg">CBOM not found</p>
        <Link to="/" className="text-cyan-400 text-sm mt-4 inline-block">← Back to Dashboard</Link>
      </div>
    );
  }

  const components = cbom.components || [];
  const vulnerabilities = cbom.vulnerabilities || [];

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <Link
            to={`/scan/${scanId}`}
            className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-cyan-400 mb-2 transition-colors font-medium"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Scan Results</span>
          </Link>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
              CYCLONEDX 1.5
            </span>
            <span className="text-xs text-gray-400 font-mono">Formal Cryptographic BOM</span>
          </div>
          <h1 className="page-header flex items-center gap-2.5">
            <Layers className="w-6 h-6 text-cyan-400" />
            <span>Cryptographic Bill of Materials (CBOM)</span>
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Standardized machine-readable inventory of cryptographic assets conforming to NIST & CycloneDX specifications.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={() => handleDownload('json')} className="btn-secondary text-xs py-2 px-3" id="download-json">
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>JSON</span>
          </button>
          <button onClick={() => handleDownload('csv')} className="btn-secondary text-xs py-2 px-3" id="download-csv">
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>CSV</span>
          </button>
          <button onClick={() => handleDownload('pdf')} className="btn-primary text-xs py-2 px-3" id="download-pdf">
            <Download className="w-3.5 h-3.5" />
            <span>PDF Report</span>
          </button>
        </div>
      </div>

      {/* View Toggle */}
      <div className="flex gap-2">
        {[
          { id: 'json', label: 'CycloneDX JSON', icon: FileText },
          { id: 'table', label: 'Tabular Components', icon: Table },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setViewMode(id)}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all flex items-center gap-2 ${
              viewMode === id
                ? 'bg-cyan-400/10 text-cyan-400 border border-cyan-400/30 shadow-glow-cyan'
                : 'text-gray-400 hover:text-gray-200 border border-transparent bg-white/[0.03]'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            <span>{label}</span>
          </button>
        ))}
      </div>

      {/* JSON View */}
      {viewMode === 'json' && (
        <div className="glass-card overflow-hidden">
          <div className="px-6 py-3 border-b border-white/5 flex items-center justify-between">
            <span className="text-xs text-gray-400 font-mono">CycloneDX Schema {cbom.specVersion || '1.5'}</span>
            <button
              onClick={() => {
                navigator.clipboard.writeText(JSON.stringify(cbom, null, 2));
                toast.success('Copied to clipboard');
              }}
              className="text-xs text-gray-400 hover:text-cyan-400 flex items-center gap-1 font-mono"
            >
              <Copy className="w-3 h-3" />
              <span>Copy Schema</span>
            </button>
          </div>
          <pre className="p-6 text-xs font-mono text-gray-300 overflow-auto max-h-[600px] leading-relaxed">
            <code dangerouslySetInnerHTML={{
              __html: syntaxHighlight(JSON.stringify(cbom, null, 2))
            }} />
          </pre>
        </div>
      )}

      {/* Table View */}
      {viewMode === 'table' && (
        <div className="space-y-6">
          {/* Components Table */}
          <div className="glass-card overflow-hidden">
            <div className="px-6 py-3 border-b border-white/5">
              <h3 className="text-sm font-semibold text-gray-300">Components ({components.length})</h3>
            </div>
            <table className="w-full">
              <thead>
                <tr className="table-header">
                  <th className="px-6 py-3 text-left">Name</th>
                  <th className="px-6 py-3 text-left">Type</th>
                  <th className="px-6 py-3 text-left">PQC Status</th>
                  <th className="px-6 py-3 text-left">Risk</th>
                  <th className="px-6 py-3 text-left">Key Exchange</th>
                </tr>
              </thead>
              <tbody>
                {components.map((comp, i) => {
                  const props = Object.fromEntries(
                    (comp.properties || []).map((p) => [p.name, p.value])
                  );
                  return (
                    <tr key={i} className="table-row">
                      <td className="px-6 py-3 text-sm font-mono text-gray-300">{comp.name}</td>
                      <td className="px-6 py-3 text-sm text-gray-400">{comp.type}</td>
                      <td className="px-6 py-3">
                        <StatusPill status={props['ciphersight:pqc_status']} />
                      </td>
                      <td className="px-6 py-3 font-mono text-sm text-gray-300">
                        {props['ciphersight:risk_score']}
                      </td>
                      <td className="px-6 py-3 text-sm text-gray-400">
                        {props['ciphersight:key_exchange'] || 'N/A'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Vulnerabilities Table */}
          {vulnerabilities.length > 0 && (
            <div className="glass-card overflow-hidden">
              <div className="px-6 py-3 border-b border-white/5">
                <h3 className="text-sm font-semibold text-red-400">⚠️ Vulnerabilities ({vulnerabilities.length})</h3>
              </div>
              <table className="w-full">
                <thead>
                  <tr className="table-header">
                    <th className="px-6 py-3 text-left">ID</th>
                    <th className="px-6 py-3 text-left">Description</th>
                    <th className="px-6 py-3 text-left">Severity</th>
                    <th className="px-6 py-3 text-left">Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerabilities.map((vuln, i) => {
                    const severity = vuln.ratings?.[0]?.severity || 'unknown';
                    return (
                      <tr key={i} className="table-row">
                        <td className="px-6 py-3 text-xs font-mono text-gray-500">{vuln.id}</td>
                        <td className="px-6 py-3 text-sm text-gray-300">{vuln.description}</td>
                        <td className="px-6 py-3">
                          <SeverityPill severity={severity} />
                        </td>
                        <td className="px-6 py-3 text-xs text-gray-400">{vuln.recommendation?.substring(0, 100)}...</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }) {
  const colors = {
    QUANTUM_SAFE: 'badge-safe',
    HYBRID_READY: 'badge-hybrid',
    VULNERABLE: 'badge-vulnerable',
  };
  return <span className={colors[status] || 'badge-queued'}>{status || 'N/A'}</span>;
}

function SeverityPill({ severity }) {
  const colors = {
    critical: 'bg-red-500/20 text-red-400 border-red-400/20',
    high: 'bg-orange-500/20 text-orange-400 border-orange-400/20',
    medium: 'bg-amber-500/20 text-amber-400 border-amber-400/20',
    low: 'bg-emerald-500/20 text-emerald-400 border-emerald-400/20',
  };
  return (
    <span className={`status-badge border ${colors[severity] || colors.medium}`}>
      {severity}
    </span>
  );
}

function syntaxHighlight(json) {
  return json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"([^"]+)":/g, '<span style="color: #7C4DFF">"$1"</span>:')
    .replace(/: "([^"]*)"/g, ': <span style="color: #00E676">"$1"</span>')
    .replace(/: (\d+)/g, ': <span style="color: #00E5FF">$1</span>')
    .replace(/: (true|false)/g, ': <span style="color: #FFD600">$1</span>')
    .replace(/: null/g, ': <span style="color: #B0BEC5">null</span>');
}
