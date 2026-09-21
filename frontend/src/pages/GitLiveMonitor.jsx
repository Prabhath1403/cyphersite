import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  GitBranch,
  GitCommit,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  ArrowRight,
  Copy,
  Check,
  ExternalLink,
  ShieldCheck,
  RefreshCw,
  Play,
  Code2,
  Database,
  Network,
  Layers,
  Activity,
  Radio,
  FileCode,
  ShieldAlert,
  Search,
  Eye,
  Settings,
  Send,
} from 'lucide-react';
import toast from 'react-hot-toast';
import {
  getGitMonitorStatus,
  getGitMonitorEvents,
  startGitWatcher,
  stopGitWatcher,
  checkPushesNow,
  getGitWebhookInfo,
  simulateGitPush,
  getRemediationPresets,
} from '../api/client';
import { useGitMonitorSocket } from '../hooks/useGitMonitorSocket';
import PQCBadge from '../components/PQCBadge';

export default function GitLiveMonitor() {
  const queryClient = useQueryClient();
  const { connected, latestEvent } = useGitMonitorSocket();

  // Watcher config state
  const [repoInput, setRepoInput] = useState('Prabhath1403/cyphersite');
  const [branchInput, setBranchInput] = useState('main');
  const [pollInterval, setPollInterval] = useState(3.0);
  const [githubToken, setGithubToken] = useState('');
  const [copiedWebhook, setCopiedWebhook] = useState(false);
  const [showTestWebhookModal, setShowTestWebhookModal] = useState(false);
  const [testPresetId, setTestPresetId] = useState('fix_rsa_to_mlkem');

  const [logs, setLogs] = useState([
    {
      time: new Date().toLocaleTimeString(),
      text: 'DAEMON ONLINE: Second-to-second GitHub push observer listening.',
      type: 'info',
    },
    {
      time: new Date().toLocaleTimeString(),
      text: 'READY: Continuous single-file incremental AST analyzer armed.',
      type: 'info',
    },
  ]);

  // Queries
  const { data: statusData, refetch: refetchStatus } = useQuery({
    queryKey: ['git-monitor-status'],
    queryFn: getGitMonitorStatus,
    refetchInterval: 3000,
  });

  const { data: eventsData = [], refetch: refetchEvents } = useQuery({
    queryKey: ['git-events'],
    queryFn: () => getGitMonitorEvents({ limit: 30 }),
    refetchInterval: 3000,
  });

  const { data: webhookInfo } = useQuery({
    queryKey: ['git-webhook-info'],
    queryFn: getGitWebhookInfo,
  });

  const { data: presets = [] } = useQuery({
    queryKey: ['git-presets'],
    queryFn: getRemediationPresets,
  });

  // Keep repository name synced if active watcher exists
  useEffect(() => {
    if (statusData?.watcher?.repository) {
      setRepoInput(statusData.watcher.repository);
    }
    if (statusData?.watcher?.branch) {
      setBranchInput(statusData.watcher.branch);
    }
  }, [statusData]);

  // Handle incoming live WebSocket telemetry event
  useEffect(() => {
    if (latestEvent) {
      setLogs((prev) => [
        {
          time: new Date().toLocaleTimeString(),
          text: `⚡ INBOUND PUSH DETECTED: [${latestEvent.repository}] ${latestEvent.file_path} (commit ${latestEvent.commit_id?.slice(0, 7)})`,
          type: 'push',
        },
        {
          time: new Date().toLocaleTimeString(),
          text: `🔍 INCREMENTAL AST SCAN: ${latestEvent.diff_summary} (latency: ${latestEvent.duration_ms}ms)`,
          type: latestEvent.vulnerabilities_fixed > 0 ? 'remediation' : 'scan',
        },
        {
          time: new Date().toLocaleTimeString(),
          text: `🔄 AUTO-SYNCHRONIZED: Crypto Inventory & Topology Graph updated across the platform.`,
          type: 'success',
        },
        ...prev.slice(0, 30),
      ]);
    }
  }, [latestEvent]);

  // Mutation: Start/Update Continuous Push Monitoring
  const startWatcherMutation = useMutation({
    mutationFn: startGitWatcher,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['git-monitor-status'] });
      toast.success(`Started continuous second-to-second push monitoring on ${repoInput} (${branchInput})`);
      setLogs((prev) => [
        {
          time: new Date().toLocaleTimeString(),
          text: `👀 OBSERVING: Started second-to-second polling on GitHub: ${repoInput} @ ${branchInput}`,
          type: 'info',
        },
        ...prev.slice(0, 30),
      ]);
    },
    onError: (err) => {
      toast.error(`Failed to start watcher: ${err.message}`);
    },
  });

  // Mutation: Stop Push Monitoring
  const stopWatcherMutation = useMutation({
    mutationFn: stopGitWatcher,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['git-monitor-status'] });
      toast.success('Stopped continuous push monitoring.');
      setLogs((prev) => [
        {
          time: new Date().toLocaleTimeString(),
          text: `🛑 STOPPED: Continuous observer paused.`,
          type: 'info',
        },
        ...prev.slice(0, 30),
      ]);
    },
  });

  // Mutation: Check For Pushes Now
  const checkNowMutation = useMutation({
    mutationFn: checkPushesNow,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['git-events'] });
      queryClient.invalidateQueries({ queryKey: ['git-monitor-status'] });
      queryClient.invalidateQueries({ queryKey: ['crypto-assets'] });
      queryClient.invalidateQueries({ queryKey: ['crypto-graph'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });

      if (data.pushes_detected > 0) {
        toast.success(`Detected and incrementally scanned ${data.pushes_detected} pushed file change(s)!`);
      } else {
        toast.success('Checked GitHub: No new developer pushes since last check.');
      }
    },
    onError: (err) => {
      toast.error(`Check failed: ${err.message}`);
    },
  });

  // Mutation: Test Inbound Webhook Delivery
  const testWebhookMutation = useMutation({
    mutationFn: simulateGitPush,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['git-events'] });
      queryClient.invalidateQueries({ queryKey: ['git-monitor-status'] });
      queryClient.invalidateQueries({ queryKey: ['crypto-assets'] });
      queryClient.invalidateQueries({ queryKey: ['crypto-graph'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
      setShowTestWebhookModal(false);

      if (data.vulnerabilities_fixed > 0) {
        toast.success(`Inbound Push Processed: ${data.file_path} fixed (${data.vulnerabilities_fixed} vulnerability remediated)!`);
      } else {
        toast.success(`Inbound Push Processed: ${data.file_path} scanned.`);
      }
    },
    onError: (err) => {
      toast.error(`Test failed: ${err.message}`);
    },
  });

  const handleToggleWatcher = () => {
    if (statusData?.watcher?.active) {
      stopWatcherMutation.mutate();
    } else {
      startWatcherMutation.mutate({
        repository: repoInput,
        branch: branchInput,
        mode: 'remote',
        interval: pollInterval,
        token: githubToken || undefined,
      });
    }
  };

  const handleTestWebhook = () => {
    const p = presets.find((item) => item.id === testPresetId) || presets[0];
    if (!p) return;
    testWebhookMutation.mutate({
      repository: repoInput,
      branch: branchInput,
      file_path: p.file_path,
      code_content: p.code_after,
      commit_message: p.commit_message,
      author: 'Security Engineer <security@ciphersight.io>',
      commit_id: `gh-${Math.random().toString(36).substring(2, 9)}`,
    });
  };

  const copyWebhookUrl = () => {
    const fullUrl = `${window.location.origin}/api/git-monitor/webhook`;
    navigator.clipboard.writeText(fullUrl);
    setCopiedWebhook(true);
    toast.success('Webhook URL copied to clipboard');
    setTimeout(() => setCopiedWebhook(false), 2000);
  };

  const isWatcherActive = statusData?.watcher?.active;
  const totalPushes = statusData?.total_events_processed || eventsData.length;
  const totalFixed = eventsData.reduce((acc, ev) => acc + (ev.vulnerabilities_fixed || 0), 0);

  return (
    <div className="space-y-8 animate-fadeIn pb-12">
      {/* ── Header ────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/[0.08] pb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500/20 via-cyan-400/10 to-indigo-500/20 border border-cyan-400/30 flex items-center justify-center text-cyan-400 shadow-glow-cyan">
              <Eye className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold text-white tracking-tight">Git Push Monitor</h1>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-400/10 text-cyan-300 font-mono border border-cyan-400/30 font-semibold uppercase tracking-wider">
                  Continuous Observer
                </span>
              </div>
              <p className="text-sm text-gray-400">
                Second-to-second GitHub push observer with single-file incremental AST scanning
              </p>
            </div>
          </div>
        </div>

        {/* Live Badges */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium border ${
            isWatcherActive
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-white/[0.04] border-white/[0.08] text-gray-400'
          }`}>
            <span className={`w-2 h-2 rounded-full ${isWatcherActive ? 'bg-emerald-400 animate-ping' : 'bg-gray-500'}`} />
            <span>{isWatcherActive ? 'MONITORING GITHUB PUSHES' : 'OBSERVER IDLE'}</span>
          </div>

          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono border ${
            connected
              ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
          }`}>
            <Radio className="w-3.5 h-3.5" />
            <span>{connected ? 'LIVE STREAM CONNECTED' : 'STREAM CONNECTING...'}</span>
          </div>
        </div>
      </div>

      {/* ── KPI Metric Cards ──────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-navy-900/60 border border-white/[0.08] backdrop-blur-xl">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Inbound Pushes</span>
            <GitCommit className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{totalPushes}</div>
          <p className="text-[11px] text-gray-500 mt-1">Commits captured from GitHub</p>
        </div>

        <div className="p-4 rounded-xl bg-navy-900/60 border border-white/[0.08] backdrop-blur-xl">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Vulnerabilities Fixed</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">{totalFixed}</div>
          <p className="text-[11px] text-gray-500 mt-1">Remediated automatically upon push</p>
        </div>

        <div className="p-4 rounded-xl bg-navy-900/60 border border-white/[0.08] backdrop-blur-xl">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Scan Latency</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-300 font-mono">
            {eventsData[0]?.duration_ms ? `${eventsData[0].duration_ms}ms` : '< 20ms'}
          </div>
          <p className="text-[11px] text-gray-500 mt-1">Single-file incremental AST analysis</p>
        </div>

        <div className="p-4 rounded-xl bg-navy-900/60 border border-white/[0.08] backdrop-blur-xl">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">App Sync Posture</span>
            <Activity className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-sm font-bold text-purple-300 font-mono mt-1">GRAPH & INVENTORY</div>
          <p className="text-[11px] text-gray-500 mt-1">Real-time reactive synchronization</p>
        </div>
      </div>

      {/* ── Continuous Repository Push Observer Configuration ──── */}
      <div className="p-6 rounded-2xl bg-navy-900/80 border border-white/[0.08] backdrop-blur-2xl shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/[0.08] pb-4 mb-5">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Settings className="w-4 h-4 text-cyan-400" />
              Repository Push Observer Settings
            </h2>
            <p className="text-xs text-gray-400">
              CipherSight monitors this GitHub repository second-to-second. Whenever a developer pushes changes, only the modified file is retrieved and scanned.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => checkNowMutation.mutate()}
              disabled={checkNowMutation.isPending}
              className="px-3.5 py-2 rounded-xl bg-white/[0.05] hover:bg-white/[0.1] border border-white/[0.1] text-gray-200 text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${checkNowMutation.isPending ? 'animate-spin' : ''}`} />
              <span>Check GitHub for Pushes Now</span>
            </button>

            <button
              onClick={() => setShowTestWebhookModal(true)}
              className="px-3.5 py-2 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-400/30 text-cyan-300 text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer"
            >
              <Send className="w-3.5 h-3.5 text-cyan-400" />
              <span>Test Webhook Payload</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
          <div className="md:col-span-5">
            <label className="text-xs font-medium text-gray-300 mb-1 block">
              GitHub Repository (owner/repo)
            </label>
            <input
              type="text"
              value={repoInput}
              onChange={(e) => setRepoInput(e.target.value)}
              placeholder="e.g. Prabhath1403/cyphersite"
              className="w-full px-3 py-2.5 rounded-xl bg-navy-950/80 border border-white/[0.08] text-white text-xs font-mono focus:outline-none focus:border-cyan-400"
            />
          </div>

          <div className="md:col-span-2">
            <label className="text-xs font-medium text-gray-300 mb-1 block">Branch</label>
            <input
              type="text"
              value={branchInput}
              onChange={(e) => setBranchInput(e.target.value)}
              placeholder="main"
              className="w-full px-3 py-2.5 rounded-xl bg-navy-950/80 border border-white/[0.08] text-white text-xs font-mono focus:outline-none focus:border-cyan-400"
            />
          </div>

          <div className="md:col-span-2">
            <label className="text-xs font-medium text-gray-300 mb-1 block">Polling Frequency</label>
            <select
              value={pollInterval}
              onChange={(e) => setPollInterval(parseFloat(e.target.value))}
              className="w-full px-3 py-2.5 rounded-xl bg-navy-950/80 border border-white/[0.08] text-white text-xs font-mono focus:outline-none focus:border-cyan-400"
            >
              <option value={1.5}>Every 1.5s</option>
              <option value={3.0}>Every 3.0s</option>
              <option value={5.0}>Every 5.0s</option>
              <option value={10.0}>Every 10.0s</option>
            </select>
          </div>

          <div className="md:col-span-3">
            <button
              onClick={handleToggleWatcher}
              disabled={startWatcherMutation.isPending || stopWatcherMutation.isPending}
              className={`w-full py-2.5 px-4 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer ${
                isWatcherActive
                  ? 'bg-rose-500/20 border border-rose-500/40 text-rose-300 hover:bg-rose-500/30'
                  : 'bg-cyan-500 hover:bg-cyan-400 text-navy-950 font-bold shadow-glow-cyan'
              }`}
            >
              {isWatcherActive ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-rose-400 animate-pulse" />
                  <span>Pause Push Monitoring</span>
                </>
              ) : (
                <>
                  <Eye className="w-4 h-4" />
                  <span>Start Continuous Monitoring</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Status Line */}
        <div className="mt-4 pt-3 border-t border-white/[0.04] flex flex-wrap items-center justify-between text-xs text-gray-400 font-mono gap-2">
          <div className="flex items-center gap-2">
            <span className="text-gray-500">Watched Target:</span>
            <span className="text-cyan-300 font-semibold">{repoInput}</span>
            <span className="text-gray-600">|</span>
            <span className="text-gray-500">Branch:</span>
            <span className="text-white">{branchInput}</span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-gray-500">Last Checked Commit:</span>
            <span className="text-emerald-400">{statusData?.watcher?.last_commit_sha?.slice(0, 8) || 'Listening...'}</span>
          </div>
        </div>
      </div>

      {/* ── Main Content Grid: Live Feed (Left) | System Sync & Webhooks (Right) ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Live Terminal Telemetry & Real-Time Feed */}
        <div className="lg:col-span-7 space-y-6">
          {/* Live Telemetry Terminal */}
          <div className="p-5 rounded-2xl bg-black/90 border border-cyan-500/20 backdrop-blur-2xl shadow-2xl flex flex-col h-[340px]">
            <div className="flex items-center justify-between border-b border-white/[0.08] pb-3 mb-3">
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                </div>
                <span className="text-xs font-mono font-semibold text-gray-400 ml-2 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  Push Telemetry Stream
                </span>
              </div>
              <span className="text-[10px] font-mono text-cyan-400/80 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                SECOND-TO-SECOND
              </span>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1 font-mono text-xs">
              {logs.map((log, index) => (
                <div key={index} className="flex items-start gap-2 leading-relaxed">
                  <span className="text-[10px] text-gray-500 shrink-0 select-none">[{log.time}]</span>
                  <span
                    className={
                      log.type === 'remediation'
                        ? 'text-emerald-400 font-semibold'
                        : log.type === 'push'
                        ? 'text-cyan-300'
                        : log.type === 'success'
                        ? 'text-purple-300'
                        : 'text-gray-300'
                    }
                  >
                    {log.text}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Jump Action Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Link
              to="/inventory"
              className="p-4 rounded-xl bg-navy-900/60 border border-white/[0.08] hover:border-cyan-400/40 transition-all group flex items-center justify-between block"
            >
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
                  <Database className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white group-hover:text-cyan-300">Crypto Inventory</h3>
                  <p className="text-[11px] text-gray-400">View real-time updated findings</p>
                </div>
              </div>
              <ArrowRight className="w-4 h-4 text-gray-500 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
            </Link>

            <Link
              to="/graph"
              className="p-4 rounded-xl bg-navy-900/60 border border-white/[0.08] hover:border-purple-400/40 transition-all group flex items-center justify-between block"
            >
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-purple-500/10 border border-purple-400/30 flex items-center justify-center text-purple-400 group-hover:scale-105 transition-transform">
                  <Network className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white group-hover:text-purple-300">Topology Graph</h3>
                  <p className="text-[11px] text-gray-400">See node change to Quantum-Safe</p>
                </div>
              </div>
              <ArrowRight className="w-4 h-4 text-gray-500 group-hover:text-purple-400 group-hover:translate-x-0.5 transition-all" />
            </Link>
          </div>
        </div>

        {/* Right Column: GitHub Webhook Setup Guide */}
        <div className="lg:col-span-5 space-y-6">
          <div className="p-5 rounded-2xl bg-navy-900/80 border border-white/[0.08] backdrop-blur-2xl">
            <h3 className="text-sm font-bold text-white mb-1 flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-cyan-400" />
              GitHub Push Webhook Setup
            </h3>
            <p className="text-xs text-gray-400 mb-3">
              Configure this webhook in your GitHub repository settings so GitHub automatically sends push events directly to CipherSight upon every commit.
            </p>

            <div className="flex items-center gap-2 mb-3">
              <input
                type="text"
                readOnly
                value={`${typeof window !== 'undefined' ? window.location.origin : ''}/api/git-monitor/webhook`}
                className="flex-1 px-3 py-2 rounded-lg bg-navy-950/80 border border-white/[0.08] text-cyan-300 font-mono text-xs truncate"
              />
              <button
                onClick={copyWebhookUrl}
                className="px-3 py-2 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] border border-white/[0.1] text-gray-300 hover:text-white transition-all flex items-center gap-1.5 text-xs cursor-pointer"
              >
                {copiedWebhook ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedWebhook ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.04] text-[11px] text-gray-400 space-y-1.5">
              <p className="font-semibold text-gray-300">Quick 3-step setup on GitHub:</p>
              <p>1. Open your repository on GitHub → <span className="text-white">Settings</span> → <span className="text-white">Webhooks</span></p>
              <p>2. Click <span className="text-cyan-400 font-semibold">Add webhook</span> and paste the Payload URL</p>
              <p>3. Choose <code className="text-cyan-300">application/json</code> and trigger on <code className="text-cyan-300">Just the 'push' event</code></p>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-navy-900/60 border border-white/[0.08]">
            <h4 className="text-xs font-bold text-white mb-2 uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              How CipherSight Monitors & Scans
            </h4>
            <div className="space-y-2 text-xs text-gray-400 leading-relaxed">
              <p>• Developers commit & push code on GitHub normally using their terminal or IDE.</p>
              <p>• CipherSight detects the push within 2 seconds via active polling or immediate webhook delivery.</p>
              <p>• Only the <span className="text-white font-semibold">single changed file</span> is downloaded and parsed with AST in &lt;20ms.</p>
              <p>• If a vulnerability was fixed (e.g. RSA replaced with ML-KEM), old vulnerable findings are cleared and the new secure posture is immediately reflected in the <span className="text-cyan-300 font-medium">Topology Graph</span> and <span className="text-cyan-300 font-medium">Crypto Inventory</span>.</p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Real-Time Commit & Remediation Audit Stream ────────── */}
      <div className="p-6 rounded-2xl bg-navy-900/80 border border-white/[0.08] backdrop-blur-2xl">
        <div className="flex items-center justify-between border-b border-white/[0.08] pb-4 mb-4">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Detected Inbound Pushes & Remediation Audit Trail
            </h3>
            <p className="text-xs text-gray-400">
              Live chronological feed of every commit detected, affected file diff, and remediation delta
            </p>
          </div>
          <button
            onClick={() => refetchEvents()}
            className="p-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-gray-400 hover:text-white transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {eventsData.length === 0 ? (
          <div className="py-10 text-center text-gray-500 text-xs">
            No developer pushes recorded yet. Start continuous push monitoring above or test a webhook delivery!
          </div>
        ) : (
          <div className="divide-y divide-white/[0.06] overflow-x-auto">
            {eventsData.map((event) => (
              <div key={event.id} className="py-3 flex items-center justify-between gap-4 text-xs font-mono">
                <div className="flex items-center gap-3 min-w-0">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${
                    event.action === 'remediated'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : event.action === 'new_vulnerabilities'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  }`}>
                    {event.action}
                  </span>
                  <div className="truncate">
                    <span className="text-white font-semibold">{event.file_path}</span>
                    <span className="text-gray-500 ml-2 truncate">({event.commit_message})</span>
                  </div>
                </div>

                <div className="flex items-center gap-4 shrink-0 text-gray-400 text-[11px]">
                  {event.vulnerabilities_fixed > 0 && (
                    <span className="text-emerald-400 font-semibold">
                      +{event.vulnerabilities_fixed} Remediated
                    </span>
                  )}
                  <span className="text-gray-500">{event.duration_ms ? `${event.duration_ms}ms` : '< 20ms'}</span>
                  <span className="text-gray-500">
                    {event.created_at ? new Date(event.created_at).toLocaleTimeString() : 'Just now'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Test Inbound Webhook Payload Modal ─────────────────── */}
      {showTestWebhookModal && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-navy-900 border border-white/[0.1] rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/[0.08] pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Send className="w-4 h-4 text-cyan-400" />
                Test Inbound GitHub Push Webhook
              </h3>
              <button
                onClick={() => setShowTestWebhookModal(false)}
                className="text-gray-400 hover:text-white text-xs p-1"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-gray-400 leading-relaxed">
              Verify that CipherSight's webhook listener correctly ingests a push event, isolates the changed file, executes the incremental AST scan, and updates the inventory and graph.
            </p>

            <div className="space-y-2">
              <label className="text-xs font-semibold text-gray-300">Select Test Push Scenario</label>
              <div className="space-y-2">
                {presets.map((p) => (
                  <button
                    key={p.id}
                    onClick={() => setTestPresetId(p.id)}
                    className={`w-full p-3 rounded-xl border text-left text-xs transition-all ${
                      testPresetId === p.id
                        ? 'bg-cyan-500/10 border-cyan-400/40 text-white'
                        : 'bg-white/[0.02] border-white/[0.06] text-gray-400 hover:bg-white/[0.04]'
                    }`}
                  >
                    <div className="font-bold mb-0.5">{p.title}</div>
                    <div className="text-[10px] text-gray-500 font-mono">{p.file_path} — {p.commit_message}</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-white/[0.08] flex items-center justify-end gap-2">
              <button
                onClick={() => setShowTestWebhookModal(false)}
                className="px-4 py-2 rounded-xl text-xs font-medium text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleTestWebhook}
                disabled={testWebhookMutation.isPending}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-navy-950 flex items-center gap-1.5 transition-all shadow-glow-cyan cursor-pointer disabled:opacity-50"
              >
                {testWebhookMutation.isPending ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Send className="w-3.5 h-3.5" />
                )}
                <span>Deliver Test Push Webhook</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
