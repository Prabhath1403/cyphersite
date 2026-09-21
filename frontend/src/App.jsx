import React, { useState } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  ScanLine,
  Database,
  Network,
  Milestone,
  Cpu,
  Cloud,
  GitBranch,
  ShieldCheck,
  Search,
  Activity,
  ChevronRight,
  ExternalLink,
  Menu,
  X,
  Bell,
  Layers,
  History,
  FolderGit2,
} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanDetail from './pages/ScanDetail';
import AssetDetail from './pages/AssetDetail';
import CBOMReport from './pages/CBOMReport';
import CryptoInventory from './pages/CryptoInventory';
import DependencyGraph from './pages/DependencyGraph';
import MigrationRoadmap from './pages/MigrationRoadmap';
import CloudScanner from './pages/CloudScanner';
import GitLiveMonitor from './pages/GitLiveMonitor';
import AIAdvisor from './pages/AIAdvisor';
import { useGitMonitorSocket } from './hooks/useGitMonitorSocket';
import { ProjectScopeProvider, useProjectScope } from './context/ProjectScopeContext';
import ProjectHistoryDrawer from './components/ProjectHistoryDrawer';

// Unchanged original navbar items as requested
const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/scan/new', label: 'New Scan', icon: ScanLine },
  { path: '/inventory', label: 'Crypto Inventory', icon: Database },
  { path: '/graph', label: 'Topology Graph', icon: Network },
  { path: '/roadmap', label: 'Migration Roadmap', icon: Milestone },
  { path: '/git-monitor', label: 'Git Live Monitor', icon: GitBranch },
  { path: '/cloud', label: 'Cloud Infrastructure', icon: Cloud },
  { path: '/ai', label: 'AI Advisor', icon: Cpu },
];

function Sidebar({ mobileOpen, setMobileOpen }) {
  const location = useLocation();
  const { openHistory, activeProject, scansList } = useProjectScope();

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40 lg:hidden backdrop-blur-sm"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={`fixed left-0 top-0 h-full w-64 bg-navy-900/95 backdrop-blur-2xl border-r border-white/[0.08] z-40 flex flex-col transition-transform duration-300 lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="p-5 border-b border-white/[0.08] flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 group" onClick={() => setMobileOpen(false)}>
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500/20 via-cyan-400/10 to-emerald-500/20 border border-cyan-400/30 flex items-center justify-center text-cyan-400 shadow-glow-cyan group-hover:scale-105 transition-all">
              <ShieldCheck className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h1 className="text-base font-bold text-white tracking-tight font-sans">CipherSight</h1>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-400/10 text-cyan-300 font-mono font-semibold border border-cyan-400/20">
                  PQC
                </span>
              </div>
              <p className="text-[10px] text-gray-400 tracking-wider uppercase font-medium">Enterprise Intelligence</p>
            </div>
          </Link>
          <button
            onClick={() => setMobileOpen(false)}
            className="lg:hidden text-gray-400 hover:text-white p-1"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* ChatGPT-style Project History Trigger Button */}
        <div className="px-3.5 pt-3 pb-2">
          <button
            onClick={() => {
              setMobileOpen(false);
              openHistory();
            }}
            className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-400/25 text-xs text-cyan-300 transition-all group shadow-glow-cyan/15 cursor-pointer"
            title="Open Project History (ChatGPT style)"
          >
            <div className="flex items-center gap-2 truncate">
              <History className="w-4 h-4 text-cyan-400 group-hover:rotate-[-20deg] transition-transform" />
              <span className="font-semibold truncate">Project History</span>
            </div>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-400/20 text-cyan-200">
              {scansList.length}
            </span>
          </button>
        </div>

        {/* Active Project Indicator Card */}
        {activeProject && (
          <div className="px-3.5 pb-2">
            <div className="px-3 py-2 rounded-lg bg-navy-950/80 border border-white/[0.06] text-xs space-y-1">
              <div className="flex items-center justify-between text-[10px] text-gray-400 font-mono">
                <span>ACTIVE SCOPE</span>
                <span className="text-cyan-400">ISOLATED</span>
              </div>
              <div className="font-mono text-white text-xs font-semibold truncate flex items-center gap-1.5" title={activeProject.target}>
                <FolderGit2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="truncate">{activeProject.target}</span>
              </div>
            </div>
          </div>
        )}

        {/* Navigation Items (Unchanged) */}
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          <div className="px-3 py-2 text-[10px] font-semibold text-gray-400 uppercase tracking-widest">
            Core Modules
          </div>
          {navItems.map(({ path, label, icon: Icon }) => {
            const isActive = location.pathname === path;
            return (
              <Link
                key={path}
                to={path}
                onClick={() => setMobileOpen(false)}
                className={`flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-400/20 shadow-glow-cyan'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                }`}
              >
                <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-cyan-400' : 'text-gray-400 group-hover:text-gray-200'}`} />
                <span className="flex-1">{label}</span>
                {isActive && <ChevronRight className="w-3.5 h-3.5 text-cyan-400/60" />}
              </Link>
            );
          })}
        </nav>

        {/* Engine Compliance & Status Footer */}
        <div className="p-4 border-t border-white/[0.08] bg-navy-950/40">
          <div className="rounded-lg p-3 bg-white/[0.02] border border-white/[0.05] space-y-2">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-emerald-400" />
                Discovery Engine
              </span>
              <span className="text-emerald-400 font-mono font-medium">READY</span>
            </div>
            <div className="text-[10px] text-gray-400 flex items-center justify-between font-mono">
              <span>NIST FIPS 203/204</span>
              <span>CNSA 2.0</span>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}

function TopHeader({ setMobileOpen }) {
  const { openHistory, activeProject } = useProjectScope();

  return (
    <header className="sticky top-0 z-30 h-16 bg-navy-950/80 backdrop-blur-xl border-b border-white/[0.08] px-6 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <button
          onClick={() => setMobileOpen(true)}
          className="lg:hidden text-gray-400 hover:text-white p-1 rounded"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Extra Project History Button in Top Header */}
        <button
          onClick={openHistory}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-navy-900/90 hover:bg-navy-800 border border-cyan-400/30 text-xs text-gray-200 transition-all shadow-glow-cyan/20 cursor-pointer group"
          title="Open Project History (ChatGPT style)"
        >
          <History className="w-4 h-4 text-cyan-400 group-hover:rotate-[-20deg] transition-transform" />
          <span className="text-gray-400 hidden sm:inline">Project:</span>
          <span className="text-cyan-300 font-mono font-semibold max-w-[170px] truncate">
            {activeProject?.target || 'Select Project'}
          </span>
          <ChevronRight className="w-3 h-3 text-gray-500" />
        </button>

        {/* Quick Search Shortcut */}
        <Link
          to="/inventory"
          className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-navy-900/80 hover:bg-navy-800 border border-white/10 text-xs text-gray-400 hover:text-gray-200 transition-colors w-64"
        >
          <Search className="w-3.5 h-3.5 text-gray-400" />
          <span>Quick search inventory...</span>
          <kbd className="ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-gray-400">
            /
          </kbd>
        </Link>
      </div>

      <div className="flex items-center gap-3">
        {/* Standards Pill */}
        <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>NIST Post-Quantum Compliant</span>
        </div>

        {/* New Scan Action Button */}
        <Link to="/scan/new" className="btn-primary py-1.5 px-3 text-xs">
          <ScanLine className="w-3.5 h-3.5" />
          <span>Run Scan</span>
        </Link>
      </div>
    </header>
  );
}

function AppContent() {
  const [mobileOpen, setMobileOpen] = useState(false);
  useGitMonitorSocket();

  return (
    <div className="flex min-h-screen bg-navy-950 text-gray-100 selection:bg-slate-700/50 selection:text-white">
      <Sidebar mobileOpen={mobileOpen} setMobileOpen={setMobileOpen} />
      <div className="flex-1 lg:ml-64 flex flex-col min-w-0">
        <TopHeader setMobileOpen={setMobileOpen} />
        <main className="flex-1 p-6 md:p-8 max-w-7xl w-full mx-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan/new" element={<NewScan />} />
            <Route path="/scan/:scanId" element={<ScanDetail />} />
            <Route path="/asset/:assetId" element={<AssetDetail />} />
            <Route path="/cbom/:scanId" element={<CBOMReport />} />
            <Route path="/inventory" element={<CryptoInventory />} />
            <Route path="/graph" element={<DependencyGraph />} />
            <Route path="/roadmap" element={<MigrationRoadmap />} />
            <Route path="/git-monitor" element={<GitLiveMonitor />} />
            <Route path="/cloud" element={<CloudScanner />} />
            <Route path="/ai" element={<AIAdvisor />} />
          </Routes>
        </main>
      </div>

      {/* ChatGPT-style Project History Drawer - high z-index slide-over */}
      <ProjectHistoryDrawer />
    </div>
  );
}

export default function App() {
  return (
    <ProjectScopeProvider>
      <AppContent />
    </ProjectScopeProvider>
  );
}
