import React, { createContext, useContext, useState, useEffect, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getScans } from '../api/client';
import toast from 'react-hot-toast';

const ProjectScopeContext = createContext(null);

const STORAGE_KEY = 'ciphersight_active_project_id';

export function ProjectScopeProvider({ children }) {
  // Read initial active project id from localStorage
  const [activeProjectId, setActiveProjectIdState] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem(STORAGE_KEY) || '';
    }
    return '';
  });

  // ChatGPT-style History Drawer state
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);

  // Fetch all completed scans/projects
  const { data: scansData, isLoading: isLoadingScans, refetch: refetchScans } = useQuery({
    queryKey: ['all-scans-projects'],
    queryFn: () => getScans({ limit: 100 }),
    refetchInterval: 12000,
  });

  const scansList = useMemo(() => {
    return scansData?.scans || scansData?.items || (Array.isArray(scansData) ? scansData : []);
  }, [scansData]);

  // If no project is currently selected, automatically default to the latest scan
  useEffect(() => {
    if (scansList.length > 0) {
      if (!activeProjectId || !scansList.some((s) => s.id === activeProjectId)) {
        const latestId = scansList[0].id;
        setActiveProjectIdState(latestId);
        if (typeof window !== 'undefined') {
          localStorage.setItem(STORAGE_KEY, latestId);
        }
      }
    }
  }, [scansList, activeProjectId]);

  // Active project object
  const activeProject = useMemo(() => {
    if (!scansList.length) return null;
    return scansList.find((s) => s.id === activeProjectId) || scansList[0];
  }, [scansList, activeProjectId]);

  // Switch active project
  const selectProject = (scanOrId) => {
    const id = typeof scanOrId === 'object' ? scanOrId.id : scanOrId;
    const targetObj = scansList.find((s) => s.id === id);
    setActiveProjectIdState(id);
    if (typeof window !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, id);
    }
    if (targetObj) {
      toast.success(`Active Project: ${targetObj.target}`, { id: 'project-switch' });
    }
    setIsHistoryOpen(false);
  };

  const openHistory = () => setIsHistoryOpen(true);
  const closeHistory = () => setIsHistoryOpen(false);
  const toggleHistory = () => setIsHistoryOpen((prev) => !prev);

  const value = {
    activeProject,
    activeProjectId: activeProject?.id || activeProjectId,
    selectProject,
    scansList,
    isLoadingScans,
    refetchScans,
    isHistoryOpen,
    openHistory,
    closeHistory,
    toggleHistory,
  };

  return <ProjectScopeContext.Provider value={value}>{children}</ProjectScopeContext.Provider>;
}

export function useProjectScope() {
  const context = useContext(ProjectScopeContext);
  if (!context) {
    throw new Error('useProjectScope must be used within a ProjectScopeProvider');
  }
  return context;
}
