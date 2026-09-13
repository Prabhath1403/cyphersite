/**
 * CertCard — PQC certificate card display with badge preview and Lucide icons.
 */
import React from 'react';
import { Award, Download, QrCode, ShieldCheck, Key, Calendar, Fingerprint, ExternalLink } from 'lucide-react';
import { useCertificate } from '../hooks/useScanResults';

export default function CertCard({ assetId }) {
  const { data: cert, isLoading, error } = useCertificate(assetId);

  if (isLoading) {
    return (
      <div className="glass-card p-6 animate-pulse">
        <div className="h-4 bg-white/5 rounded w-1/3 mb-4" />
        <div className="h-20 bg-white/5 rounded" />
      </div>
    );
  }

  if (error || !cert) return null;

  const isQuantumSafe = cert.status === 'FULLY_QUANTUM_SAFE';

  return (
    <div className={`glass-card overflow-hidden border ${isQuantumSafe ? 'border-emerald-400/30' : 'border-cyan-400/30'}`}>
      {/* Header ribbon */}
      <div className={`px-6 py-3.5 border-b ${isQuantumSafe ? 'bg-emerald-500/10 border-emerald-400/20' : 'bg-cyan-500/10 border-cyan-400/20'}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {isQuantumSafe ? (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            ) : (
              <Award className="w-4 h-4 text-cyan-400" />
            )}
            <h3 className={`text-xs font-bold uppercase tracking-wider ${isQuantumSafe ? 'text-emerald-400' : 'text-cyan-400'}`}>
              PQC Cryptographic Attestation
            </h3>
          </div>
          <span className={`text-[11px] font-mono font-semibold px-2.5 py-0.5 rounded-full border ${
            isQuantumSafe
              ? 'bg-emerald-400/20 border-emerald-400/30 text-emerald-300'
              : 'bg-cyan-400/20 border-cyan-400/30 text-cyan-300'
          }`}>
            {cert.status?.replace(/_/g, ' ')}
          </span>
        </div>
      </div>

      <div className="p-6 space-y-5">
        {/* Certificate details */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
            <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
              <Key className="w-3.5 h-3.5 text-cyan-400" />
              <span>Certificate ID</span>
            </div>
            <p className="text-xs font-mono text-gray-200 break-all select-all">{cert.cert_id}</p>
          </div>

          <div className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
            <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
              <Fingerprint className="w-3.5 h-3.5 text-indigo-400" />
              <span>Digest Fingerprint</span>
            </div>
            <p className="text-xs font-mono text-gray-200 break-all select-all">{cert.fingerprint?.substring(0, 32)}...</p>
          </div>

          <div className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
            <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
              <Calendar className="w-3.5 h-3.5 text-emerald-400" />
              <span>Issued Timestamp</span>
            </div>
            <p className="text-xs font-mono text-gray-200">{new Date(cert.issued_at).toLocaleString()}</p>
          </div>

          <div className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
            <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
              <Calendar className="w-3.5 h-3.5 text-amber-400" />
              <span>Attestation Expiry</span>
            </div>
            <p className="text-xs font-mono text-gray-200">{new Date(cert.valid_until).toLocaleString()}</p>
          </div>
        </div>

        {/* Verified Algorithms */}
        {cert.algorithms_verified?.length > 0 && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Verified Primitive Standards</p>
            <div className="flex flex-wrap gap-2">
              {cert.algorithms_verified.map((algo) => (
                <span key={algo} className="px-2.5 py-1 bg-cyan-400/10 border border-cyan-400/20 rounded-md text-xs font-mono text-cyan-300">
                  {algo}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Badge & QR */}
        <div className="flex flex-wrap gap-3 pt-4 border-t border-white/5">
          {cert.badge_svg_url && (
            <a
              href={cert.badge_svg_url}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary text-xs py-2 px-3 inline-flex items-center gap-2"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Download Badge (SVG)</span>
            </a>
          )}
          {cert.qr_url && (
            <a
              href={cert.qr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary text-xs py-2 px-3 inline-flex items-center gap-2"
            >
              <QrCode className="w-3.5 h-3.5 text-emerald-400" />
              <span>Verification QR Code</span>
            </a>
          )}
        </div>
      </div>
    </div>
  );
}
