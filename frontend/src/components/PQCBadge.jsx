/**
 * PQCBadge — Color-coded chip showing PQC readiness status.
 */
import React from 'react';

const STATUS_CONFIG = {
  QUANTUM_SAFE: {
    label: 'Quantum Safe',
    className: 'badge-safe',
    icon: '🟢',
  },
  HYBRID_READY: {
    label: 'Hybrid Ready',
    className: 'badge-hybrid',
    icon: '🟡',
  },
  VULNERABLE: {
    label: 'Vulnerable',
    className: 'badge-vulnerable',
    icon: '🔴',
  },
  INCONCLUSIVE: {
    label: 'Inconclusive',
    className: 'badge-inconclusive',
    icon: '🟠',
  },
};

export default function PQCBadge({ status, size = 'sm' }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.VULNERABLE;

  return (
    <span className={`${config.className} ${size === 'lg' ? 'px-4 py-2 text-sm' : ''}`}>
      <span>{config.icon}</span>
      {config.label}
    </span>
  );
}
