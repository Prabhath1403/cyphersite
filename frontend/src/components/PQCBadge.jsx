/**
 * PQCBadge — Color-coded chip showing PQC readiness status with crisp Lucide icons.
 */
import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, HelpCircle } from 'lucide-react';

const STATUS_CONFIG = {
  QUANTUM_SAFE: {
    label: 'Quantum Safe',
    className: 'badge-safe',
    Icon: ShieldCheck,
    dotColor: 'bg-emerald-400',
  },
  HYBRID_READY: {
    label: 'Hybrid Ready',
    className: 'badge-hybrid',
    Icon: ShieldAlert,
    dotColor: 'bg-amber-400',
  },
  VULNERABLE: {
    label: 'Vulnerable',
    className: 'badge-vulnerable',
    Icon: AlertTriangle,
    dotColor: 'bg-rose-400',
  },
  INCONCLUSIVE: {
    label: 'Inconclusive',
    className: 'badge-inconclusive',
    Icon: HelpCircle,
    dotColor: 'bg-amber-300',
  },
};

export default function PQCBadge({ status, size = 'sm', showIcon = true }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.VULNERABLE;
  const { Icon } = config;

  return (
    <span className={`${config.className} ${size === 'lg' ? 'px-3.5 py-1.5 text-xs font-semibold' : 'text-[11px]'}`}>
      {showIcon && <Icon className={size === 'lg' ? 'w-3.5 h-3.5' : 'w-3 h-3'} />}
      <span>{config.label}</span>
    </span>
  );
}
