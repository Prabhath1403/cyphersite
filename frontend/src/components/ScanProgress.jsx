/**
 * ScanProgress — Real-time WebSocket progress bar with step labels and Lucide vector icons.
 */
import React from 'react';
import { Search, Lock, Atom, FileCode, Award, CheckCircle2, Activity, AlertTriangle } from 'lucide-react';
import useScanSocket from '../hooks/useScanSocket';

const SCAN_STEPS = [
  { key: 'discovery', label: 'Discovery', icon: Search },
  { key: 'tls_scan', label: 'TLS Scan', icon: Lock },
  { key: 'pqc_check', label: 'PQC Check', icon: Atom },
  { key: 'cbom_build', label: 'CBOM Build', icon: FileCode },
  { key: 'cert_gen', label: 'Certificates', icon: Award },
  { key: 'complete', label: 'Complete', icon: CheckCircle2 },
];

export default function ScanProgress({ scanId }) {
  const { progress, event, message, isConnected, isComplete, error } = useScanSocket(scanId);

  const currentStepIndex = SCAN_STEPS.findIndex((s) => s.key === event);

  return (
    <div className="glass-card p-6 space-y-6 animate-fade-in border border-cyan-500/20">
      {/* Connection Status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            Real-Time Engine Pipeline
          </h3>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
          <span className="text-gray-400">{isConnected ? 'Telemetry Active' : 'Offline'}</span>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-lg p-4 text-rose-400 text-sm flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Progress Bar */}
      <div className="space-y-2">
        <div className="flex justify-between items-center text-xs">
          <span className="font-mono text-gray-300">{message || 'Processing queue...'}</span>
          <span className="font-mono font-bold text-cyan-400">{Math.max(0, progress)}%</span>
        </div>
        <div className="h-2.5 bg-navy-950 rounded-full overflow-hidden border border-white/5 shadow-inner">
          <div
            className={`h-full rounded-full transition-all duration-700 ease-out ${
              isComplete && !error
                ? 'bg-gradient-to-r from-emerald-500 to-emerald-400 shadow-glow-emerald'
                : error
                ? 'bg-gradient-to-r from-rose-500 to-rose-400'
                : 'bg-gradient-to-r from-cyan-600 via-cyan-400 to-indigo-400 shadow-glow-cyan'
            }`}
            style={{ width: `${Math.max(0, Math.min(100, progress))}%` }}
          />
        </div>
      </div>

      {/* Step Indicators */}
      <div className="flex items-center justify-between py-2 overflow-x-auto">
        {SCAN_STEPS.map((step, i) => {
          const StepIcon = step.icon;
          const isActive = step.key === event;
          const isPast = i < currentStepIndex;
          const isFinished = isComplete && !error;

          return (
            <div key={step.key} className="flex flex-col items-center gap-2 relative min-w-[64px]">
              <div
                className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all duration-300 ${
                  isActive
                    ? 'bg-cyan-400/20 border-2 border-cyan-400 shadow-glow-cyan scale-110'
                    : isPast || isFinished
                    ? 'bg-emerald-400/15 border border-emerald-400/40 text-emerald-400'
                    : 'bg-navy-900 border border-white/10 text-gray-500'
                }`}
              >
                <StepIcon
                  className={`w-4 h-4 ${
                    isActive
                      ? 'text-cyan-400 animate-pulse'
                      : isPast || isFinished
                      ? 'text-emerald-400'
                      : 'text-gray-500'
                  }`}
                />
              </div>
              <span
                className={`text-[10px] font-mono tracking-wider uppercase font-semibold ${
                  isActive ? 'text-cyan-300' : isPast || isFinished ? 'text-emerald-400' : 'text-gray-500'
                }`}
              >
                {step.label}
              </span>
              {/* Connector line */}
              {i < SCAN_STEPS.length - 1 && (
                <div
                  className={`absolute top-5 left-full h-0.5 -translate-y-1/2 transition-colors duration-500 ${
                    isPast || isFinished ? 'bg-emerald-400/40' : 'bg-white/10'
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
