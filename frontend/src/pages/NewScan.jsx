/**
 * NewScan — Scan input form with target and depth selection.
 */
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { createScan } from '../api/client';

export default function NewScan() {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [scanDepth, setScanDepth] = useState('quick');

  const mutation = useMutation({
    mutationFn: createScan,
    onSuccess: (data) => {
      toast.success('Scan queued successfully!');
      navigate(`/scan/${data.scan_id}`);
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'Failed to create scan');
    },
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target.trim()) {
      toast.error('Please enter a target');
      return;
    }
    mutation.mutate({ target: target.trim(), scan_depth: scanDepth });
  };

  return (
    <div className="max-w-2xl mx-auto space-y-8 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="page-header">New Scan</h1>
        <p className="text-gray-400 mt-1">Enter a target to scan for PQC readiness</p>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="glass-card p-8 space-y-6">
        {/* Target Input */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Target Domain / IP / CIDR
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g., example.com, 192.168.1.0/24, api.service.io"
            className="input-field text-lg"
            autoFocus
            id="scan-target-input"
          />
          <p className="text-xs text-gray-500 mt-2">
            Accepts domain names, IP addresses, or CIDR ranges
          </p>
        </div>

        {/* Scan Depth Toggle */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-3">
            Scan Depth
          </label>
          <div className="grid grid-cols-2 gap-4">
            {[
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
            ].map(({ value, label, desc, time }) => (
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
          disabled={mutation.isPending || !target.trim()}
          className="btn-primary w-full text-lg py-4"
          id="start-scan-btn"
        >
          {mutation.isPending ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Queuing Scan...
            </span>
          ) : (
            '🚀 Start Scan'
          )}
        </button>
      </form>

      {/* Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { icon: '🔍', title: 'Discovery', desc: 'DNS + port scanning to find all TLS endpoints' },
          { icon: '🔐', title: 'TLS Analysis', desc: 'Deep cipher suite & certificate inspection' },
          { icon: '⚛️', title: 'PQC Assessment', desc: 'NIST FIPS 203/204/205 compliance check' },
        ].map(({ icon, title, desc }) => (
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
