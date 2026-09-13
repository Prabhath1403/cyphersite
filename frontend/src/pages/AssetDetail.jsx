/**
 * AssetDetail — Enterprise cryptographic asset view with TLS fingerprint, PQC assessment, and certificate.
 */
import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Lock,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lightbulb,
  Copy,
  Check,
  Globe,
  Server,
  Key,
  Layers,
  AlertOctagon,
} from 'lucide-react';
import { useAssetDetail } from '../hooks/useScanResults';
import PQCBadge from '../components/PQCBadge';
import CertCard from '../components/CertCard';
import toast from 'react-hot-toast';

export default function AssetDetail() {
  const { assetId } = useParams();
  const { data: asset, isLoading } = useAssetDetail(assetId);
  const [copiedIndex, setCopiedIndex] = useState(null);

  const handleCopyRec = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    toast.success('Recommendation copied');
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-gray-500">
        <div className="w-6 h-6 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin mb-3" />
        <p className="text-xs">Loading cryptographic fingerprint...</p>
      </div>
    );
  }

  if (!asset) {
    return (
      <div className="glass-card text-center py-16">
        <AlertOctagon className="w-10 h-10 text-gray-600 mx-auto mb-3" />
        <p className="text-gray-300 text-lg font-semibold">Cryptographic Asset Not Found</p>
        <p className="text-xs text-gray-500 mt-1 mb-4">The specified asset ID does not exist or has expired.</p>
        <Link to="/" className="btn-secondary text-xs inline-flex items-center gap-1.5">
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Return to Dashboard</span>
        </Link>
      </div>
    );
  }

  const { tls_fingerprint = {}, pqc_assessment = {} } = asset;

  return (
    <div className="space-y-8 animate-fade-in max-w-6xl">
      {/* Header */}
      <div>
        <Link
          to={`/scan/${asset.scan_id}`}
          className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-cyan-400 mb-3 transition-colors font-medium"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Scan Analysis</span>
        </Link>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-400/10 border border-cyan-400/20 text-cyan-400">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold font-mono text-white tracking-tight">{asset.hostname}</h1>
              <div className="flex flex-wrap items-center gap-3 mt-1.5 text-xs text-gray-400 font-mono">
                <span className="flex items-center gap-1">
                  <Globe className="w-3 h-3 text-gray-500" />
                  <span>IP: {asset.ip_address || '—'}</span>
                </span>
                <span>•</span>
                <span>Port: {asset.port}</span>
                <span>•</span>
                <span className="capitalize">Service: {asset.service_type?.replace(/_/g, ' ')}</span>
              </div>
            </div>
          </div>
          <PQCBadge status={pqc_assessment.pqc_status} size="lg" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* TLS Fingerprint */}
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-white/5">
            <Lock className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-white">
              Cryptographic & TLS Fingerprint
            </h2>
          </div>

          <InfoRow label="TLS Protocols" value={tls_fingerprint.tls_versions?.join(', ') || 'N/A'} />
          <InfoRow label="Key Exchange" value={tls_fingerprint.key_exchange || 'N/A'} />
          <InfoRow label="Cert Chain Depth" value={tls_fingerprint.cert_chain_length || 'N/A'} />
          <InfoRow label="HSTS Enforcement" value={tls_fingerprint.hsts_enabled ? 'Active' : 'Disabled'} />
          <InfoRow label="OCSP Stapling" value={tls_fingerprint.ocsp_stapling ? 'Enabled' : 'Disabled'} />

          {/* Certificate */}
          {tls_fingerprint.certificate && (
            <div className="pt-4 border-t border-white/5 space-y-2.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-gray-400">
                <Key className="w-3.5 h-3.5 text-indigo-400" />
                <span>Active X.509 Leaf Certificate</span>
              </div>
              <InfoRow label="Public Key Algo" value={tls_fingerprint.certificate.public_key_algorithm || 'N/A'} />
              <InfoRow label="Key Length" value={`${tls_fingerprint.certificate.key_size || 'N/A'} bits`} />
              <InfoRow label="Signature Scheme" value={tls_fingerprint.certificate.signature_algorithm || 'N/A'} />
              <InfoRow
                label="Subject CN"
                value={
                  tls_fingerprint.certificate.subject?.commonName ||
                  JSON.stringify(tls_fingerprint.certificate.subject || {})
                }
              />
              <InfoRow label="Expiration" value={tls_fingerprint.certificate.not_after || 'N/A'} />
            </div>
          )}

          {/* Cipher Suites */}
          {tls_fingerprint.cipher_suites?.length > 0 && (
            <div className="pt-4 border-t border-white/5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                  Negotiated Cipher Suites
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 text-gray-400">
                  {tls_fingerprint.cipher_suites.length} detected
                </span>
              </div>
              <div className="max-h-52 overflow-y-auto space-y-1.5 pr-1">
                {tls_fingerprint.cipher_suites.map((suite, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between py-1.5 px-2.5 rounded bg-navy-900/60 border border-white/[0.04] text-xs font-mono"
                  >
                    <span className="text-cyan-300 truncate max-w-[280px]">{suite.name}</span>
                    <span className="text-gray-500 shrink-0">{suite.key_size} bit</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* PQC Assessment + Cert */}
        <div className="space-y-6">
          {/* Risk Score */}
          <div className="glass-card p-6">
            <div className="flex items-center gap-2 mb-4 pb-3 border-b border-white/5">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold uppercase tracking-wider text-white">
                Quantum Vulnerability Score
              </h2>
            </div>
            <div className="flex items-center gap-6">
              <div className="relative w-24 h-24 shrink-0">
                <svg className="w-24 h-24 -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="42" fill="none" stroke="#101C2E" strokeWidth="8" />
                  <circle
                    cx="50" cy="50" r="42" fill="none"
                    stroke={
                      pqc_assessment.risk_score >= 80 ? '#F43F5E' :
                      pqc_assessment.risk_score >= 60 ? '#F97316' :
                      pqc_assessment.risk_score >= 40 ? '#EAB308' :
                      '#10B981'
                    }
                    strokeWidth="8"
                    strokeDasharray={`${(pqc_assessment.risk_score || 0) * 2.64} 264`}
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-2xl font-black font-mono text-white">
                    {pqc_assessment.risk_score?.toFixed(0) || '—'}
                  </span>
                </div>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Threat Exposure Tier</p>
                <p className={`text-xl font-bold mt-0.5 ${
                  pqc_assessment.risk_score >= 80 ? 'text-rose-400' :
                  pqc_assessment.risk_score >= 60 ? 'text-orange-400' :
                  pqc_assessment.risk_score >= 40 ? 'text-amber-400' :
                  'text-emerald-400'
                }`}>
                  {pqc_assessment.risk_score >= 80 ? 'Critical Quantum Exposure' :
                   pqc_assessment.risk_score >= 60 ? 'High Harvest Risk' :
                   pqc_assessment.risk_score >= 40 ? 'Moderate Margin' :
                   'Low Risk / Post-Quantum Ready'}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  Evaluated against Shor (discrete log/factoring) & Grover (symmetric search) bounds.
                </p>
              </div>
            </div>
          </div>

          {/* Vulnerabilities */}
          {pqc_assessment.vulnerabilities?.length > 0 && (
            <div className="glass-card p-6 border-rose-500/20 bg-rose-500/[0.02]">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-rose-400">
                  Detected Vulnerabilities ({pqc_assessment.vulnerabilities.length})
                </h3>
              </div>
              <ul className="space-y-2">
                {pqc_assessment.vulnerabilities.map((v, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-xs text-gray-300">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0" />
                    <span>{v}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommendations */}
          {pqc_assessment.recommendations?.length > 0 && (
            <div className="glass-card p-6 border-cyan-500/20 bg-cyan-500/[0.02]">
              <div className="flex items-center gap-2 mb-3">
                <Lightbulb className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                  Remediation & Migration Steps
                </h3>
              </div>
              <ul className="space-y-2">
                {pqc_assessment.recommendations.map((r, i) => (
                  <li
                    key={i}
                    className="flex items-center justify-between gap-3 p-2 rounded bg-white/[0.02] border border-white/[0.04] text-xs text-gray-300 hover:bg-white/[0.04] transition-colors"
                  >
                    <span className="flex-1">{r}</span>
                    <button
                      onClick={() => handleCopyRec(r, i)}
                      className="p-1.5 rounded hover:bg-white/10 text-gray-400 hover:text-cyan-300 transition-colors shrink-0"
                      title="Copy recommendation"
                    >
                      {copiedIndex === i ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* PQC Certificate */}
          <CertCard assetId={assetId} />
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="flex justify-between items-start py-2 border-b border-white/[0.02]">
      <span className="text-xs text-gray-400 w-1/3">{label}</span>
      <span className="text-xs text-gray-200 font-mono text-right w-2/3 break-all">{value}</span>
    </div>
  );
}
