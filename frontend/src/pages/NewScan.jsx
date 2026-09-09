/**
 * NewScan — Scan input form with target and depth selection.
 */
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { createScan, submitSourceScan } from '../api/client';

export default function NewScan() {
  const navigate = useNavigate();
  const [scanType, setScanType] = useState('network'); // 'network' | 'source'
  const [target, setTarget] = useState('');
  const [scanDepth, setScanDepth] = useState('quick');

  const networkMutation = useMutation({
    mutationFn: createScan,
    onSuccess: (data) => {
      toast.success('Network scan queued successfully!');
      navigate(`/scan/${data.scan_id}`);
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'Failed to create network scan');
    },
  });

  const sourceMutation = useMutation({
    mutationFn: submitSourceScan,
    onSuccess: (data) => {
      toast.success(`Source scan complete! Found ${data.total_assets} cryptographic usages.`);
      navigate(`/scan/${data.id}`);
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'Failed to scan source code');
    },
  });

  const isPending = networkMutation.isPending || sourceMutation.isPending;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target.trim()) {
      toast.error(scanType === 'network' ? 'Please enter a target domain/IP' : 'Please enter a repo path or Git URL');
      return;
    }
    if (scanType === 'network') {
      networkMutation.mutate({ target: target.trim(), scan_depth: scanDepth });
    } else {
      sourceMutation.mutate({ path: target.trim(), scan_depth: scanDepth });
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-8 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="page-header">New Scan</h1>
        <p className="text-gray-400 mt-1">
          {scanType === 'network'
            ? 'Discover public TLS endpoints and evaluate Post-Quantum Cryptography posture'
            : 'Scan source code repositories to audit cryptographic libraries, ciphers, and algorithms'}
        </p>
      </div>

      {/* Mode Selector Tabs */}
      <div className="flex rounded-xl bg-navy-800/60 p-1 border border-white/10">
        <button
          type="button"
          onClick={() => { setScanType('network'); setScanDepth('quick'); }}
          className={`flex-1 py-3 px-4 rounded-lg font-medium text-sm transition-all duration-300 flex items-center justify-center gap-2 ${
            scanType === 'network'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 shadow-glow-cyan'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <span>🌐</span> Network Endpoints
        </button>
        <button
          type="button"
          onClick={() => { setScanType('source'); setScanDepth('standard'); }}
          className={`flex-1 py-3 px-4 rounded-lg font-medium text-sm transition-all duration-300 flex items-center justify-center gap-2 ${
            scanType === 'source'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 shadow-glow-cyan'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <span>💻</span> Source Code Repository
        </button>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="glass-card p-8 space-y-6">
        {/* Target Input */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            {scanType === 'network' ? 'Target Domain / IP / CIDR' : 'Repository Path or Git Clone URL'}
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={
              scanType === 'network'
                ? 'e.g., example.com, 192.168.1.0/24, api.service.io'
                : 'e.g., /home/user/my-python-app, ./backend, or https://github.com/org/repo.git'
            }
            className="input-field text-lg"
            autoFocus
            id="scan-target-input"
          />
          <p className="text-xs text-gray-500 mt-2">
            {scanType === 'network'
              ? 'Accepts domain names, IP addresses, or CIDR ranges'
              : 'Accepts local filesystem directory paths or public/private Git repository URLs'}
          </p>
        </div>

        {/* Scan Depth Toggle */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-3">
            Scan Depth
          </label>
          <div className="grid grid-cols-2 gap-4">
            {(scanType === 'network'
              ? [
                  {
                    value: 'quick',
                    label: '⚡ Quick Scan',
                    desc: 'Target only, common TLS ports',
                    time: '~30 seconds',
                  },
                  {
                    value: 'full',
                    label: '🔬 Full Scan',
                    desc: 'Subdomain enum + deep TLS analysis',
                    time: '~2-5 minutes',
                  },
                ]
              : [
                  {
                    value: 'standard',
                    label: '⚡ Standard Scan',
                    desc: 'AST cryptographic API detection',
                    time: '~1-5 seconds',
                  },
                  {
                    value: 'deep',
                    label: '🔬 Deep Audit',
                    desc: 'Full recursive code analysis',
                    time: '~10-30 seconds',
                  },
                ]
            ).map(({ value, label, desc, time }) => (
              <button
                key={value}
                type="button"
                onClick={() => setScanDepth(value)}
                className={`p-5 rounded-xl border text-left transition-all duration-300 ${
                  scanDepth === value
                    ? 'border-cyan-400/50 bg-cyan-400/5 shadow-glow-cyan'
                    : 'border-white/10 bg-navy-800/40 hover:border-white/20'
                }`}
                id={`scan-depth-${value}`}
              >
                <p className="font-semibold text-gray-200">{label}</p>
                <p className="text-xs text-gray-400 mt-1">{desc}</p>
                <p className="text-xs text-cyan-400/60 mt-2 font-mono">{time}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={isPending || !target.trim()}
          className="btn-primary w-full text-lg py-4"
          id="start-scan-btn"
        >
          {isPending ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              {scanType === 'network' ? 'Queuing Network Scan...' : 'Scanning Source Code...'}
            </span>
          ) : (
            `🚀 Start ${scanType === 'network' ? 'Network' : 'Source'} Scan`
          )}
        </button>
      </form>

      {/* Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {(scanType === 'network'
          ? [
              { icon: '🔍', title: 'Discovery', desc: 'DNS + port scanning to find all TLS endpoints' },
              { icon: '🔐', title: 'TLS Analysis', desc: 'Deep cipher suite & certificate inspection' },
              { icon: '⚛️', title: 'PQC Assessment', desc: 'NIST FIPS 203/204/205 compliance check' },
            ]
          : [
              { icon: '🐍', title: 'Python AST', desc: 'Deterministic AST analysis of crypto libraries and API calls' },
              { icon: '📜', title: 'CBOM 1.5', desc: 'Automated CycloneDX Cryptographic Bill of Materials generation' },
              { icon: '⚛️', title: 'Quantum Audit', desc: 'Evaluates Shor’s & Grover’s attack vulnerabilities' },
            ]
        ).map(({ icon, title, desc }) => (
          <div key={title} className="glass-card p-5">
            <span className="text-2xl">{icon}</span>
            <h3 className="font-semibold text-gray-200 mt-2">{title}</h3>
            <p className="text-xs text-gray-400 mt-1">{desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
