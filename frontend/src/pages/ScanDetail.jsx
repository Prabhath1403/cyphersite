/**
 * ScanDetail — Live scan progress + results view with Lucide icons.
 */
import React from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  FileText,
  Download,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Layers,
  Lock,
  AlertOctagon,
  FileSpreadsheet,
} from 'lucide-react';
import { useScan, useAssets } from '../hooks/useScanResults';
import ScanProgress from '../components/ScanProgress';
import AssetTable from '../components/AssetTable';
import RiskHeatmap from '../components/RiskHeatmap';
import CipherChart from '../components/CipherChart';
import { downloadCBOM } from '../api/client';
import toast from 'react-hot-toast';

export default function ScanDetail() {
  const { scanId } = useParams();
  const { data: scan, isLoading } = useScan(scanId);
  const { data: assetsData } = useAssets({ scan_id: scanId });

  const isRunning = scan?.status === 'queued' || scan?.status === 'running';
  const isComplete = scan?.status === 'completed';
  const assets = assetsData?.assets || [];

  const handleDownload = async (format) => {
    try {
      await downloadCBOM(scanId, format);
      toast.success(`Downloaded ${format.toUpperCase()} report`);
    } catch {
      toast.error('Download failed');
    }
  };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-gray-500">
        <div className="w-6 h-6 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin mb-3" />
        <p className="text-xs">Loading scan telemetry...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-cyan-400 mb-2 transition-colors font-medium"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Central Command</span>
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="page-header font-mono">{scan?.target}</h1>
            <span className="text-xs px-2 py-0.5 rounded bg-white/5 border border-white/10 text-gray-300 font-mono">
              {scan?.scan_depth}
            </span>
          </div>
          <div className="flex items-center gap-4 mt-2 text-xs text-gray-400 font-mono">
            <span>Scan ID: {scan?.id}</span>
            <span>•</span>
            <span>Started: {new Date(scan?.created_at).toLocaleString()}</span>
          </div>
        </div>

        {isComplete && (
          <div className="flex flex-wrap items-center gap-2">
            <button onClick={() => handleDownload('json')} className="btn-secondary text-xs py-2 px-3">
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
              <span>JSON</span>
            </button>
            <button onClick={() => handleDownload('csv')} className="btn-secondary text-xs py-2 px-3">
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
              <span>CSV</span>
            </button>
            <button onClick={() => handleDownload('pdf')} className="btn-primary text-xs py-2 px-3">
              <Download className="w-3.5 h-3.5" />
              <span>PDF Report</span>
            </button>
            <Link to={`/cbom/${scanId}`} className="btn-secondary text-xs py-2 px-3">
              <Layers className="w-3.5 h-3.5 text-indigo-400" />
              <span>View CBOM</span>
            </Link>
          </div>
        )}
      </div>

      {/* Progress */}
      {isRunning && <ScanProgress scanId={scanId} />}

      {/* Error */}
      {scan?.status === 'failed' && (
        <div className="glass-card p-6 border-rose-500/30 bg-rose-500/10">
          <div className="flex items-center gap-2 text-rose-400 font-semibold mb-2">
            <AlertOctagon className="w-5 h-5" />
            <h3>Scan Interrupted / Failed</h3>
          </div>
          <p className="text-sm text-gray-300">{scan.error_message || 'An unknown error occurred during discovery execution'}</p>
        </div>
      )}

      {/* Results Summary */}
      {isComplete && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <StatMini label="Total Assets" value={scan.total_assets} icon={Layers} color="text-white" iconColor="text-cyan-400" />
            <StatMini label="Quantum Safe" value={scan.quantum_safe_count} icon={ShieldCheck} color="text-emerald-400" iconColor="text-emerald-400" />
            <StatMini label="Hybrid Ready" value={scan.hybrid_count} icon={ShieldAlert} color="text-amber-400" iconColor="text-amber-400" />
            <StatMini label="Vulnerable" value={scan.vulnerable_count} icon={AlertTriangle} color="text-rose-400" iconColor="text-rose-400" />
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <CipherChart assets={assets} type="status" />
            <RiskHeatmap assets={assets} />
          </div>

          {/* Asset Table */}
          <div>
            <h2 className="section-title mb-4">
              <Lock className="w-4 h-4 text-cyan-400" />
              <span>Discovered Cryptographic Assets ({assets.length})</span>
            </h2>
            <AssetTable assets={assets} />
          </div>
        </>
      )}
    </div>
  );
}

function StatMini({ label, value, icon: Icon, color = 'text-white', iconColor = 'text-gray-400' }) {
  return (
    <div className="stat-card p-4 flex items-center gap-4">
      <div className={`p-2.5 rounded-lg bg-white/[0.04] border border-white/[0.06] ${iconColor}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">{label}</p>
        <p className={`text-2xl font-extrabold font-mono mt-0.5 ${color}`}>{value ?? 0}</p>
      </div>
    </div>
  );
}
