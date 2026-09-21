import React, { useState, useMemo } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import {
  History,
  X,
  Search,
  Plus,
  FolderGit2,
  Check,
  ShieldAlert,
  ShieldCheck,
  Clock,
  ArrowRight,
  Sparkles,
  Layers,
  Network,
  Milestone,
  ExternalLink,
} from 'lucide-react';
import { useProjectScope } from '../context/ProjectScopeContext';

export default function ProjectHistoryDrawer() {
  const navigate = useNavigate();
  const location = useLocation();
  const { isHistoryOpen, closeHistory, scansList, activeProjectId, selectProject } = useProjectScope();

  const [searchTerm, setSearchTerm] = useState('');

  // Filter projects by search
  const filteredProjects = useMemo(() => {
    if (!searchTerm.trim()) return scansList;
    const q = searchTerm.toLowerCase();
    return scansList.filter(
      (s) =>
        s.target?.toLowerCase().includes(q) ||
        s.scan_type?.toLowerCase().includes(q) ||
        s.id?.toLowerCase().includes(q)
    );
  }, [scansList, searchTerm]);

  // Group projects into Today, Yesterday, and Previous
  const groupedProjects = useMemo(() => {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    const yesterday = today - 86400000;

    const groups = {
      today: [],
      yesterday: [],
      previous: [],
    };

    filteredProjects.forEach((p) => {
      const pTime = new Date(p.created_at || Date.now()).getTime();
      if (pTime >= today) {
        groups.today.push(p);
      } else if (pTime >= yesterday) {
        groups.yesterday.push(p);
      } else {
        groups.previous.push(p);
      }
    });

    return groups;
  }, [filteredProjects]);

  if (!isHistoryOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/70 backdrop-blur-md z-50 transition-opacity animate-fade-in"
        onClick={closeHistory}
      />

      {/* Slide-over Drawer (ChatGPT style) */}
      <aside className="fixed left-0 top-0 bottom-0 w-full max-w-md bg-navy-950/95 border-r border-white/10 z-50 shadow-2xl flex flex-col transform transition-transform duration-300 animate-slide-in">
        {/* Drawer Header */}
        <div className="p-4 border-b border-white/10 flex items-center justify-between bg-navy-900/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-400/20 text-cyan-400">
              <History className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <span>Project History</span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-white/10 text-gray-400">
                  {scansList.length}
                </span>
              </h2>
              <p className="text-[11px] text-gray-400">Select a project to view its isolated posture & data</p>
            </div>
          </div>

          <button
            onClick={closeHistory}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
            title="Close History"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* "+ New Project Scan" (ChatGPT "+ New Chat" equivalent) */}
        <div className="p-4 border-b border-white/5 bg-navy-950">
          <Link
            to="/scan/new"
            onClick={closeHistory}
            className="w-full py-2.5 px-3.5 rounded-xl bg-gradient-to-r from-cyan-500/20 via-cyan-400/15 to-emerald-500/20 hover:from-cyan-500/30 hover:to-emerald-500/30 border border-cyan-400/30 hover:border-cyan-400/50 text-white text-xs font-semibold flex items-center justify-between shadow-glow-cyan transition-all group"
          >
            <div className="flex items-center gap-2.5">
              <div className="p-1 rounded bg-cyan-400/20 text-cyan-300">
                <Plus className="w-4 h-4" />
              </div>
              <span>Scan New Project / Repository</span>
            </div>
            <ArrowRight className="w-3.5 h-3.5 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
          </Link>

          {/* Search Input */}
          <div className="relative mt-3">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search previous projects..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-navy-900 border border-white/10 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400/50"
            />
          </div>
        </div>

        {/* Project Items List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-5">
          {scansList.length === 0 ? (
            <div className="text-center py-16 text-gray-500 space-y-2">
              <FolderGit2 className="w-8 h-8 text-gray-600 mx-auto" />
              <p className="text-xs font-medium text-gray-400">No project scans recorded yet</p>
              <p className="text-[11px] text-gray-600 max-w-xs mx-auto">
                Run your first scan on a Git repository or code directory to start tracking projects.
              </p>
            </div>
          ) : (
            <>
              {/* Today Section */}
              {groupedProjects.today.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] font-mono text-gray-400 uppercase font-semibold tracking-wider px-1">
                    Today
                  </span>
                  {groupedProjects.today.map((p) => (
                    <ProjectCard
                      key={p.id}
                      project={p}
                      isActive={p.id === activeProjectId}
                      onSelect={() => selectProject(p.id)}
                    />
                  ))}
                </div>
              )}

              {/* Yesterday Section */}
              {groupedProjects.yesterday.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] font-mono text-gray-400 uppercase font-semibold tracking-wider px-1">
                    Yesterday
                  </span>
                  {groupedProjects.yesterday.map((p) => (
                    <ProjectCard
                      key={p.id}
                      project={p}
                      isActive={p.id === activeProjectId}
                      onSelect={() => selectProject(p.id)}
                    />
                  ))}
                </div>
              )}

              {/* Previous Section */}
              {groupedProjects.previous.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] font-mono text-gray-400 uppercase font-semibold tracking-wider px-1">
                    Previous Projects
                  </span>
                  {groupedProjects.previous.map((p) => (
                    <ProjectCard
                      key={p.id}
                      project={p}
                      isActive={p.id === activeProjectId}
                      onSelect={() => selectProject(p.id)}
                    />
                  ))}
                </div>
              )}
            </>
          )}
        </div>

        {/* Drawer Footer Status */}
        <div className="p-3 border-t border-white/10 bg-navy-950 text-[11px] text-gray-400 flex items-center justify-between font-mono">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Project Isolation Active
          </span>
          <span className="text-cyan-400 text-[10px]">ChatGPT-Style Scope</span>
        </div>
      </aside>
    </>
  );
}

function ProjectCard({ project, isActive, onSelect }) {
  const isVuln = (project.vulnerable_count || 0) > 0;

  return (
    <div
      onClick={onSelect}
      className={`p-3 rounded-xl border transition-all cursor-pointer relative group ${
        isActive
          ? 'bg-cyan-500/10 border-cyan-400/50 shadow-glow-cyan'
          : 'bg-navy-900/60 border-white/5 hover:bg-navy-800/60 hover:border-white/15'
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className={`p-2 rounded-lg border ${
              isActive
                ? 'bg-cyan-400/20 border-cyan-400/40 text-cyan-300'
                : 'bg-white/5 border-white/10 text-gray-400 group-hover:text-white'
            }`}
          >
            <FolderGit2 className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <h4
              className={`text-xs font-semibold truncate font-mono ${
                isActive ? 'text-cyan-300 font-bold' : 'text-gray-200'
              }`}
              title={project.target}
            >
              {project.target}
            </h4>
            <div className="flex items-center gap-2 mt-0.5 text-[10px] text-gray-400 font-mono">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3 text-gray-500" />
                {new Date(project.created_at || Date.now()).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                })}
              </span>
              <span>•</span>
              <span className="capitalize">{project.scan_depth || 'standard'}</span>
            </div>
          </div>
        </div>

        {/* Active Checkmark or Status Pill */}
        {isActive ? (
          <div className="flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-400/20 border border-cyan-400/30 text-cyan-300 text-[10px] font-mono font-bold whitespace-nowrap">
            <Check className="w-3 h-3" />
            <span>ACTIVE</span>
          </div>
        ) : isVuln ? (
          <span className="px-1.5 py-0.5 rounded bg-rose-500/15 border border-rose-500/25 text-rose-300 text-[10px] font-mono whitespace-nowrap">
            {project.vulnerable_count} vuln
          </span>
        ) : (
          <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/25 text-emerald-300 text-[10px] font-mono whitespace-nowrap">
            safe
          </span>
        )}
      </div>

      {/* Summary Footer on the card */}
      <div className="mt-2.5 pt-2 border-t border-white/[0.04] flex items-center justify-between text-[10px] text-gray-400">
        <span>{project.total_assets || project.quantum_safe_count + (project.vulnerable_count || 0)} Assets</span>
        <span className="text-gray-500 group-hover:text-cyan-400 flex items-center gap-1 transition-colors">
          <span>Inspect Project</span>
          <ArrowRight className="w-3 h-3" />
        </span>
      </div>
    </div>
  );
}
