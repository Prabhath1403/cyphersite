/**
 * CertCard — PQC certificate card display with badge preview.
 */
import React from 'react';
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
    <div className={`glass-card overflow-hidden ${isQuantumSafe ? 'border-emerald-400/20' : 'border-cyan-400/20'}`}>
      {/* Header ribbon */}
      <div className={`px-6 py-3 ${isQuantumSafe ? 'bg-emerald-400/10' : 'bg-cyan-400/10'}`}>
        <div className="flex items-center justify-between">
          <h3 className={`text-sm font-bold ${isQuantumSafe ? 'text-emerald-400' : 'text-cyan-400'}`}>
            🏅 PQC Certificate
          </h3>
          <span className={`text-xs font-mono px-3 py-1 rounded-full ${
            isQuantumSafe
              ? 'bg-emerald-400/20 text-emerald-400'
              : 'bg-cyan-400/20 text-cyan-400'
          }`}>
            {cert.status}
          </span>
        </div>
      </div>

      <div className="p-6 space-y-4">
        {/* Certificate details */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-gray-500 mb-1">Certificate ID</p>
            <p className="text-xs font-mono text-gray-300 break-all">{cert.cert_id}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 mb-1">Fingerprint</p>
            <p className="text-xs font-mono text-gray-300 break-all">{cert.fingerprint?.substring(0, 32)}...</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 mb-1">Issued At</p>
            <p className="text-sm text-gray-300">{new Date(cert.issued_at).toLocaleDateString()}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 mb-1">Valid Until</p>
            <p className="text-sm text-gray-300">{new Date(cert.valid_until).toLocaleDateString()}</p>
          </div>
        </div>

        {/* Verified Algorithms */}
        {cert.algorithms_verified?.length > 0 && (
          <div>
            <p className="text-xs text-gray-500 mb-2">Verified Algorithms</p>
            <div className="flex flex-wrap gap-2">
              {cert.algorithms_verified.map((algo) => (
                <span key={algo} className="px-2 py-1 bg-white/5 rounded text-xs font-mono text-cyan-400">
                  {algo}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Badge & QR */}
        <div className="flex gap-4 pt-4 border-t border-white/5">
          {cert.badge_svg_url && (
            <a
              href={cert.badge_svg_url}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary text-xs py-2 px-3"
            >
              📥 Download Badge
            </a>
          )}
          {cert.qr_url && (
            <a
              href={cert.qr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary text-xs py-2 px-3"
            >
              📱 QR Code
            </a>
          )}
        </div>
      </div>
    </div>
  );
}
