/**
 * CBOMReport — CBOM viewer with JSON syntax highlighting and download options.
 */
import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
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
      <div className="flex items-center justify-between">
        <div>
          <Link to={`/scan/${scanId}`} className="text-sm text-gray-500 hover:text-gray-300 mb-2 inline-block">
            ← Back to Scan
          </Link>
          <h1 className="page-header">CBOM Report</h1>
          <p className="text-gray-400 mt-1">CycloneDX Cryptographic Bill of Materials</p>
        </div>
        <div className="flex gap-3">
          <button onClick={() => handleDownload('json')} className="btn-secondary text-sm py-2" id="download-json">
            📄 JSON
          </button>
          <button onClick={() => handleDownload('csv')} className="btn-secondary text-sm py-2" id="download-csv">
            📊 CSV
          </button>
          <button onClick={() => handleDownload('pdf')} className="btn-primary text-sm py-2" id="download-pdf">
            📥 PDF Report
          </button>
        </div>
      </div>

      {/* View Toggle */}
      <div className="flex gap-2">
        {['json', 'table'].map((mode) => (
          <button
            key={mode}
            onClick={() => setViewMode(mode)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              viewMode === mode
                ? 'bg-cyan-400/10 text-cyan-400 border border-cyan-400/20'
                : 'text-gray-400 hover:text-gray-200 border border-transparent'
            }`}
          >
            {mode === 'json' ? '{ } JSON' : '📋 Table'}
          </button>
        ))}
      </div>

      {/* JSON View */}
      {viewMode === 'json' && (
        <div className="glass-card overflow-hidden">
          <div className="px-6 py-3 border-b border-white/5 flex items-center justify-between">
            <span className="text-xs text-gray-500 font-mono">CycloneDX {cbom.specVersion}</span>
            <button
              onClick={() => {
                navigator.clipboard.writeText(JSON.stringify(cbom, null, 2));
                toast.success('Copied to clipboard');
              }}
              className="text-xs text-gray-400 hover:text-cyan-400"
            >
              📋 Copy
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
