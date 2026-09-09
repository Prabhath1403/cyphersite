/**
 * NewScan — Scan input form with target and depth selection.
 */
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { createScan, submitSourceScan, submitContainerScan, submitBinaryScan } from '../api/client';

export default function NewScan() {
  const navigate = useNavigate();
  const [scanType, setScanType] = useState('network'); // 'network' | 'source' | 'container' | 'binary'
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

  const containerMutation = useMutation({
    mutationFn: submitContainerScan,
    onSuccess: (data) => {
      toast.success(`Container scan complete! Discovered ${data.total_assets} crypto components.`);
      navigate(`/scan/${data.id}`);
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'Failed to scan container image');
    },
  });

  const binaryMutation = useMutation({
    mutationFn: submitBinaryScan,
    onSuccess: (data) => {
      toast.success(`Binary scan complete! Discovered ${data.total_assets} symbols & crypto libraries.`);
      navigate(`/scan/${data.id}`);
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'Failed to scan compiled binary');
    },
  });

  const isPending = networkMutation.isPending || sourceMutation.isPending || containerMutation.isPending || binaryMutation.isPending;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target.trim()) {
      if (scanType === 'network') toast.error('Please enter a target domain/IP');
      else if (scanType === 'source') toast.error('Please enter a repo path or Git URL');
      else if (scanType === 'container') toast.error('Please enter an image tag, tarball path, or rootfs');
      else toast.error('Please enter a binary file path or directory');
      return;
    }
    if (scanType === 'network') {
      networkMutation.mutate({ target: target.trim(), scan_depth: scanDepth });
    } else if (scanType === 'source') {
      sourceMutation.mutate({ path: target.trim(), scan_depth: scanDepth });
    } else if (scanType === 'container') {
      containerMutation.mutate({ image: target.trim(), scan_depth: scanDepth });
    } else {
      binaryMutation.mutate({ path: target.trim(), scan_depth: scanDepth });
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-8 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="page-header">New Scan</h1>
        <p className="text-gray-400 mt-1">
          {scanType === 'network' && 'Discover public TLS endpoints and evaluate Post-Quantum Cryptography posture'}
          {scanType === 'source' && 'Scan source code repositories to audit cryptographic libraries, ciphers, and algorithms'}
          {scanType === 'container' && 'Audit container images and packages for post-quantum security and cryptographic libraries'}
          {scanType === 'binary' && 'Dissect compiled ELF, PE, and Mach-O binaries for embedded cryptographic symbols and PQC support'}
        </p>
      </div>

      {/* Mode Selector Tabs */}
      <div className="flex rounded-xl bg-navy-800/60 p-1 border border-white/10">
        <button
          type="button"
          onClick={() => { setScanType('network'); setScanDepth('quick'); }}
          className={`flex-1 py-3 px-3 rounded-lg font-medium text-xs md:text-sm transition-all duration-300 flex items-center justify-center gap-1.5 ${
            scanType === 'network'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 shadow-glow-cyan'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <span>🌐</span> Network
        </button>
        <button
          type="button"
          onClick={() => { setScanType('source'); setScanDepth('standard'); }}
          className={`flex-1 py-3 px-3 rounded-lg font-medium text-xs md:text-sm transition-all duration-300 flex items-center justify-center gap-1.5 ${
            scanType === 'source'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 shadow-glow-cyan'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <span>💻</span> Source Code
        </button>
        <button
          type="button"
          onClick={() => { setScanType('container'); setScanDepth('standard'); }}
          className={`flex-1 py-3 px-3 rounded-lg font-medium text-xs md:text-sm transition-all duration-300 flex items-center justify-center gap-1.5 ${
            scanType === 'container'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 shadow-glow-cyan'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <span>🐳</span> Container
        </button>
        <button
          type="button"
          onClick={() => { setScanType('binary'); setScanDepth('standard'); }}
          className={`flex-1 py-3 px-3 rounded-lg font-medium text-xs md:text-sm transition-all duration-300 flex items-center justify-center gap-1.5 ${
            scanType === 'binary'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 shadow-glow-cyan'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <span>⚙️</span> Binary
        </button>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="glass-card p-8 space-y-6">
        {/* Target Input */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            {scanType === 'network' && 'Target Domain / IP / CIDR'}
            {scanType === 'source' && 'Repository Path or Git Clone URL'}
            {scanType === 'container' && 'Container Image (Tag, Tarball Path, or Rootfs)'}
            {scanType === 'binary' && 'Compiled Binary File Path or Directory (ELF / PE / Mach-O)'}
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={
              scanType === 'network'
                ? 'e.g., example.com, 192.168.1.0/24, api.service.io'
                : scanType === 'source'
                ? 'e.g., /home/user/my-python-app, ./backend, or https://github.com/org/repo.git'
                : scanType === 'container'
                ? 'e.g., ubuntu:22.04, ./image.tar, or /var/lib/rootfs'
                : 'e.g., /usr/bin/app, ./libcrypto.so, /path/to/binaries, or ./app.tar'
            }
            className="input-field text-lg"
            autoFocus
            id="scan-target-input"
          />
          <p className="text-xs text-gray-500 mt-2">
            {scanType === 'network' && 'Accepts domain names, IP addresses, or CIDR ranges'}
            {scanType === 'source' && 'Accepts local filesystem directory paths or public/private Git repository URLs'}
            {scanType === 'container' && 'Accepts Docker image names/tags, OCI .tar archives, or unpacked rootfs folders'}
            {scanType === 'binary' && 'Accepts single binary executables, shared libraries (.so/.dll/.dylib), or directories'}
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
                    desc:
                      scanType === 'source'
                        ? 'AST cryptographic API detection'
                        : scanType === 'container'
                        ? 'Layer & package DB inspection'
                        : 'Symbol table & dynamic import analysis',
                    time: '~1-5 seconds',
                  },
                  {
                    value: 'deep',
                    label: '🔬 Deep Audit',
                    desc:
                      scanType === 'source'
                        ? 'Full recursive code analysis'
                        : scanType === 'container'
                        ? 'Full binary & cert extraction'
                        : 'Full string extraction & constant scan',
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
              {scanType === 'network' && 'Queuing Network Scan...'}
              {scanType === 'source' && 'Scanning Source Code...'}
              {scanType === 'container' && 'Scanning Container Image...'}
              {scanType === 'binary' && 'Dissecting Compiled Binary...'}
            </span>
          ) : (
            `🚀 Start ${
              scanType === 'network'
                ? 'Network'
                : scanType === 'source'
                ? 'Source'
                : scanType === 'container'
                ? 'Container'
                : 'Binary'
            } Scan`
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
          : scanType === 'source'
          ? [
              { icon: '🐍', title: 'Python AST', desc: 'Deterministic AST analysis of crypto libraries and API calls' },
              { icon: '📜', title: 'CBOM 1.5', desc: 'Automated CycloneDX Cryptographic Bill of Materials generation' },
              { icon: '⚛️', title: 'Quantum Audit', desc: 'Evaluates Shor’s & Grover’s attack vulnerabilities' },
            ]
          : scanType === 'container'
          ? [
              { icon: '📦', title: 'Package DBs', desc: 'Audits dpkg, apk, rpm, and site-packages databases' },
              { icon: '📂', title: 'Layer Inspection', desc: 'Extracts shared crypto binaries (.so) and root certificates' },
              { icon: '⚛️', title: 'PQC Readiness', desc: 'Classifies OpenSSL 3.x, liboqs, and crypto posture' },
            ]
          : [
              { icon: '🧩', title: 'Symbol Extraction', desc: 'Parses .dynsym, .symtab, and export/import tables across ELF/PE/Mach-O' },
              { icon: '📦', title: 'Library Linkage', desc: 'Identifies dynamically and statically linked OpenSSL, liboqs, sodium' },
              { icon: '⚛️', title: 'PQC Signatures', desc: 'Detects FIPS 203 ML-KEM, FIPS 204 ML-DSA, and quantum vulnerabilities' },
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
