/**
 * NewScan — Enterprise Multi-Modal Cryptographic Discovery Launcher.
 */
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import {
  Globe,
  Code2,
  Box,
  Binary,
  ScanLine,
  Zap,
  Search,
  CheckCircle2,
  Lock,
  GitBranch,
  KeyRound,
  FileCode,
  ShieldCheck,
  AlertTriangle,
  FolderTree,
  FileSearch,
  ExternalLink,
  Sparkles,
} from 'lucide-react';
import toast from 'react-hot-toast';
import {
  createScan,
  submitSourceScan,
  submitContainerScan,
  submitBinaryScan,
  getGitHubRepoInfo,
} from '../api/client';

const SAMPLE_TARGETS = {
  network: [
    { label: 'karunya.edu', value: 'karunya.edu', desc: 'University TLS Infrastructure' },
    { label: 'google.com', value: 'google.com', desc: 'Enterprise Cloud Gateway' },
    { label: 'cloudflare.com', value: 'cloudflare.com', desc: 'Hybrid Kyber/X25519 Edge' },
  ],
  source: [
    { label: 'paramiko/paramiko', value: 'https://github.com/paramiko/paramiko', desc: 'SSH & Asymmetric Cryptography' },
    { label: 'oauthlib/oauthlib', value: 'https://github.com/oauthlib/oauthlib', desc: 'OAuth & Token Signatures' },
    { label: 'pallets/flask', value: 'https://github.com/pallets/flask', desc: 'Web Session Hashing' },
  ],
  container: [
    { label: 'ubuntu:22.04', value: 'ubuntu:22.04', desc: 'Ubuntu 22.04 LTS (OpenSSL 3.0 + GnuTLS)' },
    { label: 'nginx:alpine', value: 'nginx:alpine', desc: 'Nginx on Alpine (OpenSSL + X.509 Certificates)' },
    { label: 'alpine:latest', value: 'alpine:latest', desc: 'Alpine Linux (Libcrypto Minimal)' },
  ],
  binary: [
    { label: '/usr/bin/openssl', value: '/usr/bin/openssl', desc: 'Standard System OpenSSL Executable' },
    { label: '/usr/lib/libcrypto.so', value: '/usr/lib/libcrypto.so', desc: 'Core Cryptographic Dynamic Library' },
  ],
};

export default function NewScan() {
  const navigate = useNavigate();
  const [scanType, setScanType] = useState('network'); // 'network' | 'source' | 'container' | 'binary'
  const [target, setTarget] = useState('');
  const [scanDepth, setScanDepth] = useState('quick');
  const [gitBranch, setGitBranch] = useState('');
  const [gitToken, setGitToken] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [repoInfo, setRepoInfo] = useState(null);
  const [isFetchingInfo, setIsFetchingInfo] = useState(false);
  const [repoInfoError, setRepoInfoError] = useState('');

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

  const handleFetchRepoInfo = async () => {
    if (!target.trim()) {
      toast.error('Please enter a GitHub repository URL or owner/repo shorthand first');
      return;
    }
    setIsFetchingInfo(true);
    setRepoInfoError('');
    try {
      const info = await getGitHubRepoInfo({
        url: target.trim(),
        token: gitToken.trim() || undefined,
      });
      setRepoInfo(info);
      if (!gitBranch && info.default_branch) {
        setGitBranch(info.default_branch);
      }
      toast.success(`Verified repository: ${info.full_name}`);
    } catch (err) {
      const msg = err.response?.data?.detail || 'Failed to fetch repository details from GitHub';
      setRepoInfoError(msg);
      toast.error(msg);
      setRepoInfo(null);
    } finally {
      setIsFetchingInfo(false);
    }
  };

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
      sourceMutation.mutate({
        path: target.trim(),
        scan_depth: scanDepth,
        branch: gitBranch.trim() || undefined,
        token: gitToken.trim() || undefined,
      });
    } else if (scanType === 'container') {
      containerMutation.mutate({ image: target.trim(), scan_depth: scanDepth });
    } else {
      binaryMutation.mutate({ path: target.trim(), scan_depth: scanDepth });
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-8 animate-fade-in">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
            DISCOVERY ENGINE
          </span>
          <span className="text-xs text-gray-400 font-mono">Multi-Modal Ingestion</span>
        </div>
        <h1 className="page-header flex items-center gap-2.5">
          <ScanLine className="w-6 h-6 text-cyan-400" />
          <span>Launch Cryptographic Scan</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Audit network perimeters, source code AST, container packages, and compiled binary symbols for post-quantum vulnerability.
        </p>
      </div>

      {/* Mode Selector Tabs */}
      <div className="flex rounded-xl bg-navy-900/90 p-1.5 border border-white/10 gap-1 shadow-subtle">
        {[
          { id: 'network', label: 'Network & TLS', icon: Globe, depth: 'quick' },
          { id: 'source', label: 'Source Code AST', icon: Code2, depth: 'standard' },
          { id: 'container', label: 'Container Image', icon: Box, depth: 'standard' },
          { id: 'binary', label: 'Compiled Binary', icon: Binary, depth: 'standard' },
        ].map(({ id, label, icon: Icon, depth }) => (
          <button
            key={id}
            type="button"
            onClick={() => {
              setScanType(id);
              setScanDepth(depth);
              setTarget('');
              setRepoInfo(null);
            }}
            className={`flex-1 py-2.5 px-3 rounded-lg font-medium text-xs md:text-sm transition-all flex items-center justify-center gap-2 ${
              scanType === id
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 shadow-glow-cyan font-semibold'
                : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.03] border border-transparent'
            }`}
          >
            <Icon className="w-4 h-4" />
            <span>{label}</span>
          </button>
        ))}
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="glass-card p-6 md:p-8 space-y-6 border border-white/10">
        {/* Target Input */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold uppercase tracking-wider text-gray-300">
              {scanType === 'network' && 'Target Hostname / IP / CIDR'}
              {scanType === 'source' && 'Repository Path or Git Clone URL'}
              {scanType === 'container' && 'Container Image (Tag, Tarball Path, or Rootfs)'}
              {scanType === 'binary' && 'Compiled Binary File Path (ELF / PE / Mach-O)'}
            </label>
            <span className="text-[11px] text-gray-500 font-mono">Required</span>
          </div>

          <input
            type="text"
            value={target}
            onChange={(e) => {
              setTarget(e.target.value);
              setRepoInfo(null);
              setRepoInfoError('');
            }}
            placeholder={
              scanType === 'network'
                ? 'e.g. karunya.edu, google.com, api.service.io'
                : scanType === 'source'
                ? 'e.g. https://github.com/paramiko/paramiko or pallets/flask'
                : scanType === 'container'
                ? 'e.g. ubuntu:22.04 or alpine:latest'
                : 'e.g. /usr/bin/openssl or ./libcrypto.so'
            }
            className="input-field text-base py-3"
            autoFocus
            id="scan-target-input"
          />

          {/* Quick Preset Buttons */}
          <div className="mt-3 flex items-center gap-2 flex-wrap">
            <span className="text-[11px] text-gray-500 flex items-center gap-1 font-medium">
              <Sparkles className="w-3 h-3 text-cyan-400" />
              <span>Quick Presets:</span>
            </span>
            {SAMPLE_TARGETS[scanType]?.map((sample) => (
              <button
                key={sample.value}
                type="button"
                onClick={() => {
                  setTarget(sample.value);
                  setRepoInfo(null);
                  setRepoInfoError('');
                }}
                className="px-2 py-1 rounded bg-white/[0.04] hover:bg-cyan-500/10 hover:border-cyan-400/30 border border-white/10 text-xs font-mono text-cyan-300 transition-colors"
                title={sample.desc}
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>

        {/* Source Code / GitHub Remote Configuration */}
        {scanType === 'source' && (
          <div className="space-y-4 pt-2 border-t border-white/[0.06]">
            <div className="flex items-center justify-between text-xs text-gray-400">
              <span className="flex items-center gap-1.5 font-semibold text-cyan-300">
                <GitBranch className="w-3.5 h-3.5" />
                <span>Git Remote & Authentication</span>
              </span>
              <button
                type="button"
                onClick={handleFetchRepoInfo}
                disabled={isFetchingInfo || !target.trim()}
                className="px-3 py-1 rounded bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-400/30 font-medium transition flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
                id="verify-github-repo-btn"
              >
                {isFetchingInfo ? (
                  <>
                    <div className="w-3 h-3 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                    <span>Verifying...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-3 h-3" />
                    <span>Verify Remote Repo</span>
                  </>
                )}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1">
                  Branch / Tag (Optional)
                </label>
                <input
                  type="text"
                  value={gitBranch}
                  onChange={(e) => setGitBranch(e.target.value)}
                  placeholder="e.g. main, master"
                  className="input-field text-xs"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-xs font-medium text-gray-300">
                    GitHub Token / PAT (Optional)
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    className="text-[11px] text-cyan-400 hover:underline"
                  >
                    {showToken ? 'Hide' : 'Show'}
                  </button>
                </div>
                <input
                  type={showToken ? 'text' : 'password'}
                  value={gitToken}
                  onChange={(e) => setGitToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                  className="input-field text-xs font-mono"
                />
              </div>
            </div>

            {/* Error badge */}
            {repoInfoError && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>{repoInfoError}</span>
              </div>
            )}

            {/* Verified Repo Card */}
            {repoInfo && (
              <div className="p-4 rounded-xl bg-navy-950 border border-cyan-500/40 space-y-2 shadow-glow-cyan animate-fade-in text-xs">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-cyan-400" />
                    <span className="font-semibold text-white">{repoInfo.full_name}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    {repoInfo.is_private ? 'Private' : 'Public'}
                  </span>
                </div>
                {repoInfo.description && (
                  <p className="text-gray-300 text-[11px]">{repoInfo.description}</p>
                )}
                <div className="flex items-center gap-4 text-gray-400 font-mono text-[11px] pt-1 border-t border-white/5">
                  <span>Branch: <strong className="text-cyan-300">{repoInfo.default_branch}</strong></span>
                  <span>Lang: <strong className="text-gray-200">{repoInfo.language || 'Python'}</strong></span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Scan Depth Selection */}
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-gray-300 mb-3">
            Execution Depth & Rigor
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {(scanType === 'network'
              ? [
                  {
                    value: 'quick',
                    label: 'Quick TLS Handshake',
                    desc: 'Direct endpoint TLS negotiation, certificate chain decoding',
                    time: '~15-30s',
                  },
                  {
                    value: 'full',
                    label: 'Full Surface Recon',
                    desc: 'Passive subdomains, cert transparency logs, cipher negotiation',
                    time: '~1-3m',
                  },
                ]
              : [
                  {
                    value: 'standard',
                    label: 'Standard Audit',
                    desc: 'AST cryptographic calls, library linkages, API extraction',
                    time: '~2-5s',
                  },
                  {
                    value: 'deep',
                    label: 'Deep Rigor Audit',
                    desc: 'Recursive dependency tree, raw constant strings & bytecode dissection',
                    time: '~10-30s',
                  },
                ]
            ).map(({ value, label, desc, time }) => (
              <button
                key={value}
                type="button"
                onClick={() => setScanDepth(value)}
                className={`p-4 rounded-xl border text-left transition-all ${
                  scanDepth === value
                    ? 'border-cyan-400/60 bg-cyan-500/10 shadow-glow-cyan'
                    : 'border-white/10 bg-navy-900/60 hover:border-white/20'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-sm text-gray-200">{label}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-cyan-300">
                    {time}
                  </span>
                </div>
                <p className="text-xs text-gray-400 mt-1">{desc}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isPending || !target.trim()}
          className="btn-primary w-full text-base py-3.5 flex items-center justify-center gap-2 shadow-glow-cyan"
        >
          {isPending ? (
            <>
              <div className="w-4 h-4 border-2 border-navy-950 border-t-transparent rounded-full animate-spin" />
              <span>Analyzing Target & Ingesting Cryptography...</span>
            </>
          ) : (
            <>
              <ScanLine className="w-4 h-4" />
              <span>Execute {scanType.toUpperCase()} Discovery Scan</span>
            </>
          )}
        </button>
      </form>

      {/* Architectural Capabilities Footer */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          {
            icon: ShieldCheck,
            title: 'NIST Standards Alignment',
            desc: 'Real-time compliance checks against FIPS 203 (ML-KEM), 204 (ML-DSA), and 205 (SLH-DSA).',
          },
          {
            icon: Lock,
            title: 'Mosca Theorem Horizon',
            desc: 'Automated evaluation of X + Y > Z risk to prevent retrospective data harvesting.',
          },
          {
            icon: FolderTree,
            title: 'CycloneDX CBOM 1.5',
            desc: 'Generates standardized Cryptographic Bill of Materials ready for DevSecOps pipelines.',
          },
        ].map(({ icon: Icon, title, desc }) => (
          <div key={title} className="glass-card p-4 border border-white/5 space-y-1.5">
            <Icon className="w-5 h-5 text-cyan-400" />
            <h3 className="font-semibold text-gray-200 text-xs">{title}</h3>
            <p className="text-[11px] text-gray-400 leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
