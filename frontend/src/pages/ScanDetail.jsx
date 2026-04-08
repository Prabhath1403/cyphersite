/**
 * ScanDetail — Live scan progress + results view.
 */
import React from 'react';
import { useParams, Link } from 'react-router-dom';
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
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500 animate-pulse">Loading scan...</div>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link to="/" className="text-sm text-gray-500 hover:text-gray-300 mb-2 inline-block">
            ← Back to Dashboard
          </Link>
          <h1 className="page-header">Scan: {scan?.target}</h1>
          <div className="flex items-center gap-4 mt-2">
            <span className="text-sm text-gray-400">Depth: {scan?.scan_depth}</span>
            <span className="text-sm text-gray-500">
              Started: {new Date(scan?.created_at).toLocaleString()}
            </span>
          </div>
        </div>

        {isComplete && (
          <div className="flex gap-3">
            <button onClick={() => handleDownload('json')} className="btn-secondary text-sm py-2">
              📄 JSON
            </button>
            <button onClick={() => handleDownload('csv')} className="btn-secondary text-sm py-2">
              📊 CSV
            </button>
            <button onClick={() => handleDownload('pdf')} className="btn-primary text-sm py-2">
              📥 PDF Report
            </button>
            <Link to={`/cbom/${scanId}`} className="btn-secondary text-sm py-2">
              📋 View CBOM
            </Link>
          </div>
        )}
      </div>

      {/* Progress */}
      {isRunning && <ScanProgress scanId={scanId} />}

      {/* Error */}
      {scan?.status === 'failed' && (
        <div className="glass-card p-6 border-red-500/20">
          <h3 className="text-red-400 font-semibold mb-2">⚠️ Scan Failed</h3>
          <p className="text-sm text-gray-400">{scan.error_message || 'An unknown error occurred'}</p>
        </div>
      )}

      {/* Results Summary */}
      {isComplete && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <StatMini label="Total Assets" value={scan.total_assets} icon="🌐" />
            <StatMini label="Quantum Safe" value={scan.quantum_safe_count} icon="🟢" color="text-emerald-400" />
            <StatMini label="Hybrid Ready" value={scan.hybrid_count} icon="🟡" color="text-amber-400" />
            <StatMini label="Vulnerable" value={scan.vulnerable_count} icon="🔴" color="text-red-400" />
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <CipherChart assets={assets} type="status" />
            <RiskHeatmap assets={assets} />
          </div>

          {/* Asset Table */}
          <div>
            <h2 className="section-title mb-4">
              <span>🔐</span> Discovered Assets
            </h2>
            <AssetTable assets={assets} />
          </div>
        </>
      )}
    </div>
  );
}

function StatMini({ label, value, icon, color = 'text-white' }) {
  return (
    <div className="glass-card p-4 flex items-center gap-4">
      <span className="text-2xl">{icon}</span>
      <div>
        <p className="text-xs text-gray-500">{label}</p>
        <p className={`text-2xl font-bold font-mono ${color}`}>{value ?? 0}</p>
      </div>
    </div>
  );
}
