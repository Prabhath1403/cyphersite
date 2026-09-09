import React from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanDetail from './pages/ScanDetail';
import AssetDetail from './pages/AssetDetail';
import CBOMReport from './pages/CBOMReport';
import CryptoInventory from './pages/CryptoInventory';
import DependencyGraph from './pages/DependencyGraph';
import MigrationRoadmap from './pages/MigrationRoadmap';
import AIAdvisor from './pages/AIAdvisor';

const navItems = [
  { path: '/', label: 'Dashboard', icon: '📊' },
  { path: '/scan/new', label: 'New Scan', icon: '🔍' },
  { path: '/inventory', label: 'Crypto Inventory', icon: '📦' },
  { path: '/graph', label: 'Topology Graph', icon: '🕸️' },
  { path: '/roadmap', label: 'Migration Roadmap', icon: '🚀' },
  { path: '/ai', label: 'AI Advisor', icon: '🧠' },
];

function Sidebar() {
  const location = useLocation();

  return (
    <aside className="fixed left-0 top-0 h-full w-64 bg-navy-900/95 backdrop-blur-xl border-r border-white/5 z-50 flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-white/5">
        <Link to="/" className="flex items-center gap-3 group">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-emerald-400 flex items-center justify-center text-lg shadow-glow-cyan group-hover:scale-110 transition-transform">
            🛡️
          </div>
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">CipherSight</h1>
            <p className="text-[10px] text-cyan-400/60 uppercase tracking-[0.2em] font-medium">Quantum Scanner</p>
          </div>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1">
        {navItems.map(({ path, label, icon }) => {
          const isActive = location.pathname === path;
          return (
            <Link
              key={path}
              to={path}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-cyan-400/10 text-cyan-400 border border-cyan-400/20 shadow-glow-cyan'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
              }`}
            >
              <span className="text-base">{icon}</span>
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-white/5">
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>v1.0.0 • PQC Scanner</span>
        </div>
      </div>
    </aside>
  );
}

export default function App() {
  return (
    <div className="flex min-h-screen bg-navy-950">
      <Sidebar />
      <main className="flex-1 ml-64 p-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan/new" element={<NewScan />} />
          <Route path="/scan/:scanId" element={<ScanDetail />} />
          <Route path="/asset/:assetId" element={<AssetDetail />} />
          <Route path="/cbom/:scanId" element={<CBOMReport />} />
          <Route path="/inventory" element={<CryptoInventory />} />
          <Route path="/graph" element={<DependencyGraph />} />
          <Route path="/roadmap" element={<MigrationRoadmap />} />
          <Route path="/ai" element={<AIAdvisor />} />
        </Routes>
      </main>
    </div>
  );
}
