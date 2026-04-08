/**
 * ScanProgress — Real-time WebSocket progress bar with step labels.
 */
import React from 'react';
import useScanSocket from '../hooks/useScanSocket';

const SCAN_STEPS = [
  { key: 'discovery', label: 'Discovery', icon: '🔍' },
  { key: 'tls_scan', label: 'TLS Scan', icon: '🔐' },
  { key: 'pqc_check', label: 'PQC Check', icon: '⚛️' },
  { key: 'cbom_build', label: 'CBOM Build', icon: '📄' },
  { key: 'cert_gen', label: 'Certificates', icon: '🏅' },
  { key: 'complete', label: 'Complete', icon: '✅' },
];

export default function ScanProgress({ scanId }) {
  const { progress, event, message, isConnected, isComplete, error } = useScanSocket(scanId);

  const currentStepIndex = SCAN_STEPS.findIndex((s) => s.key === event);

  return (
    <div className="glass-card p-6 space-y-6 animate-fade-in">
      {/* Connection Status */}
      <div className="flex items-center justify-between">
        <h3 className="section-title">
          <span>📡</span> Scan Progress
        </h3>
        <div className="flex items-center gap-2 text-xs">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
          <span className="text-gray-400">{isConnected ? 'Connected' : 'Disconnected'}</span>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400 text-sm">
          ⚠️ {error}
        </div>
      )}

      {/* Progress Bar */}
      <div className="space-y-2">
        <div className="flex justify-between items-center">
          <span className="text-sm text-gray-400">{message}</span>
          <span className="text-sm font-mono text-cyan-400">{Math.max(0, progress)}%</span>
        </div>
        <div className="h-3 bg-navy-800 rounded-full overflow-hidden border border-white/5">
          <div
            className={`h-full rounded-full transition-all duration-700 ease-out ${
              isComplete && !error
                ? 'bg-gradient-to-r from-emerald-400 to-emerald-500'
                : error
                ? 'bg-gradient-to-r from-red-500 to-red-400'
                : 'bg-gradient-to-r from-cyan-500 to-cyan-400'
            }`}
            style={{ width: `${Math.max(0, Math.min(100, progress))}%` }}
          />
        </div>
      </div>

      {/* Step Indicators */}
      <div className="flex items-center justify-between py-2">
        {SCAN_STEPS.map((step, i) => {
          const isActive = step.key === event;
          const isPast = i < currentStepIndex;
          const isFuture = i > currentStepIndex && !isComplete;

          return (
            <div key={step.key} className="flex flex-col items-center gap-2 relative">
              <div
                className={`w-10 h-10 rounded-xl flex items-center justify-center text-sm transition-all duration-500 ${
                  isActive
                    ? 'bg-cyan-400/20 border-2 border-cyan-400 shadow-glow-cyan scale-110'
                    : isPast || (isComplete && !error)
                    ? 'bg-emerald-400/20 border border-emerald-400/30'
                    : 'bg-navy-800 border border-white/10'
                }`}
              >
                {step.icon}
              </div>
              <span
                className={`text-[10px] font-medium tracking-wide ${
                  isActive ? 'text-cyan-400' : isPast ? 'text-emerald-400' : 'text-gray-500'
                }`}
              >
                {step.label}
              </span>
              {/* Connector line */}
              {i < SCAN_STEPS.length - 1 && (
                <div
                  className={`absolute top-5 left-full w-full h-0.5 -translate-y-1/2 ${
                    isPast ? 'bg-emerald-400/30' : 'bg-white/5'
                  }`}
                  style={{ width: 'calc(100% - 40px)', left: '40px' }}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
