/**
 * AssetDetail — Full asset view with TLS fingerprint, PQC assessment, and certificate.
 */
import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAssetDetail } from '../hooks/useScanResults';
import PQCBadge from '../components/PQCBadge';
import CertCard from '../components/CertCard';

export default function AssetDetail() {
  const { assetId } = useParams();
  const { data: asset, isLoading } = useAssetDetail(assetId);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500 animate-pulse">Loading asset details...</div>
      </div>
    );
  }

  if (!asset) {
    return (
      <div className="text-center py-16">
        <p className="text-gray-500 text-lg">Asset not found</p>
        <Link to="/" className="text-cyan-400 text-sm mt-4 inline-block">← Back to Dashboard</Link>
      </div>
    );
  }

  const { tls_fingerprint, pqc_assessment } = asset;

  return (
    <div className="space-y-8 animate-fade-in max-w-5xl">
      {/* Header */}
      <div>
        <Link to={`/scan/${asset.scan_id}`} className="text-sm text-gray-500 hover:text-gray-300 mb-2 inline-block">
          ← Back to Scan
        </Link>
        <div className="flex items-center gap-4">
          <h1 className="page-header">{asset.hostname}</h1>
          <PQCBadge status={pqc_assessment.pqc_status} size="lg" />
        </div>
        <div className="flex gap-4 mt-2 text-sm text-gray-400">
          <span>IP: {asset.ip_address || 'N/A'}</span>
          <span>Port: {asset.port}</span>
          <span>Service: {asset.service_type}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* TLS Fingerprint */}
        <div className="glass-card p-6 space-y-4">
          <h2 className="section-title"><span>🔐</span> TLS Fingerprint</h2>

          <InfoRow label="TLS Versions" value={tls_fingerprint.tls_versions?.join(', ') || 'N/A'} />
          <InfoRow label="Key Exchange" value={tls_fingerprint.key_exchange || 'N/A'} />
          <InfoRow label="Cert Chain Length" value={tls_fingerprint.cert_chain_length || 'N/A'} />
          <InfoRow label="HSTS" value={tls_fingerprint.hsts_enabled || 'unknown'} />
          <InfoRow label="OCSP Stapling" value={tls_fingerprint.ocsp_stapling || 'unknown'} />

          {/* Certificate */}
          {tls_fingerprint.certificate && (
            <div className="pt-4 border-t border-white/5 space-y-2">
              <h3 className="text-sm font-semibold text-gray-300">Certificate</h3>
              <InfoRow label="Algorithm" value={tls_fingerprint.certificate.public_key_algorithm || 'N/A'} />
              <InfoRow label="Key Size" value={`${tls_fingerprint.certificate.key_size || 'N/A'} bits`} />
              <InfoRow label="Signature" value={tls_fingerprint.certificate.signature_algorithm || 'N/A'} />
              <InfoRow label="Subject" value={
                tls_fingerprint.certificate.subject?.commonName ||
                JSON.stringify(tls_fingerprint.certificate.subject || {})
              } />
              <InfoRow label="Expires" value={tls_fingerprint.certificate.not_after || 'N/A'} />
            </div>
          )}

          {/* Cipher Suites */}
          {tls_fingerprint.cipher_suites?.length > 0 && (
            <div className="pt-4 border-t border-white/5">
              <h3 className="text-sm font-semibold text-gray-300 mb-2">
                Cipher Suites ({tls_fingerprint.cipher_suites.length})
              </h3>
              <div className="max-h-48 overflow-y-auto space-y-1">
                {tls_fingerprint.cipher_suites.map((suite, i) => (
                  <div key={i} className="flex items-center gap-2 py-1 px-2 rounded bg-white/[0.02] text-xs">
                    <span className="font-mono text-cyan-400 flex-1 truncate">{suite.name}</span>
                    <span className="text-gray-500">{suite.key_size}bit</span>
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
            <h2 className="section-title mb-4"><span>🛡️</span> PQC Assessment</h2>
            <div className="flex items-center gap-6 mb-6">
              <div className="relative w-24 h-24">
                <svg className="w-24 h-24 -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="42" fill="none" stroke="#1A2A40" strokeWidth="8" />
                  <circle
                    cx="50" cy="50" r="42" fill="none"
                    stroke={
                      pqc_assessment.risk_score >= 80 ? '#FF1744' :
                      pqc_assessment.risk_score >= 60 ? '#FF6D00' :
                      pqc_assessment.risk_score >= 40 ? '#FFD600' :
                      '#00E676'
                    }
                    strokeWidth="8"
                    strokeDasharray={`${(pqc_assessment.risk_score || 0) * 2.64} 264`}
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-xl font-bold font-mono text-white">
                    {pqc_assessment.risk_score?.toFixed(0) || '—'}
                  </span>
                </div>
              </div>
              <div>
                <p className="text-sm text-gray-400">Risk Score</p>
                <p className="text-lg font-semibold text-white">
                  {pqc_assessment.risk_score >= 80 ? 'Critical' :
                   pqc_assessment.risk_score >= 60 ? 'High' :
                   pqc_assessment.risk_score >= 40 ? 'Medium' :
                   'Low'}
                </p>
              </div>
            </div>
          </div>

          {/* Vulnerabilities */}
          {pqc_assessment.vulnerabilities?.length > 0 && (
            <div className="glass-card p-6 border-red-500/10">
              <h3 className="text-sm font-bold text-red-400 mb-3">⚠️ Vulnerabilities ({pqc_assessment.vulnerabilities.length})</h3>
              <ul className="space-y-2">
                {pqc_assessment.vulnerabilities.map((v, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                    <span className="text-red-400 mt-0.5">•</span>
                    {v}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommendations */}
          {pqc_assessment.recommendations?.length > 0 && (
            <div className="glass-card p-6 border-cyan-400/10">
              <h3 className="text-sm font-bold text-cyan-400 mb-3">💡 Recommendations</h3>
              <ul className="space-y-2">
                {pqc_assessment.recommendations.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-gray-300 group">
                    <span className="text-cyan-400 mt-0.5">→</span>
                    <span className="flex-1">{r}</span>
                    <button
                      onClick={() => { navigator.clipboard.writeText(r); }}
                      className="opacity-0 group-hover:opacity-100 text-xs text-gray-500 hover:text-cyan-400 transition-all"
                      title="Copy"
                    >
                      📋
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
    <div className="flex justify-between items-start py-1.5">
      <span className="text-xs text-gray-500 w-1/3">{label}</span>
      <span className="text-sm text-gray-300 font-mono text-right w-2/3 break-all">{value}</span>
    </div>
  );
}
