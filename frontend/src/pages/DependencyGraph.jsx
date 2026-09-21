import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Network,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Maximize2,
  Terminal,
  Search,
  Layers,
  FileCode,
  Lock,
  Database,
  Globe,
  ShieldAlert,
  ArrowRight,
  Sparkles,
  Info,
  Check,
  Copy,
  Download,
  Sliders,
  Move,
  Compass,
  ShieldCheck,
  ShieldX,
  Cpu,
  RefreshCw,
  FolderGit2,
  CheckCircle2,
  AlertTriangle,
  History,
} from 'lucide-react';
import { getScanGraph, getScans } from '../api/client';
import { useProjectScope } from '../context/ProjectScopeContext';
import toast from 'react-hot-toast';

// Logical architectural tiers for a single project's scan
const PIPELINE_COLUMNS = [
  { key: 'Scan', label: 'Target Project', desc: 'Scan Target', matches: (n) => n.label === 'Scan' || n.type === 'application' },
  { key: 'Host', label: 'Endpoints', desc: 'Network Hosts', matches: (n) => n.label === 'Host' || n.type === 'endpoint' },
  { key: 'File', label: 'Source Files', desc: 'Components', matches: (n) => n.label === 'File' || n.type === 'component' },
  { key: 'Algorithm', label: 'Algorithms', desc: 'Cryptographic Ciphers', matches: (n) => n.label === 'Algorithm' || n.type === 'algorithm' },
  { key: 'Other', label: 'Libraries', desc: 'Dependencies', matches: (n) => n.label === 'Other' || n.type === 'library' },
  { key: 'Data', label: 'Protected Data', desc: 'Data Assets', matches: (n) => n.label === 'Data' || n.type === 'data_asset' },
];

export default function DependencyGraph() {
  const [searchParams, setSearchParams] = useSearchParams();
  const scanIdFromUrl = searchParams.get('scanId');
  const { activeProject, activeProjectId, selectProject, openHistory, scansList } = useProjectScope();

  // Selected single scan state (strictly one project at a time)
  const selectedScanId = scanIdFromUrl || activeProjectId || (scansList[0]?.id || '');

  // Handle user selecting a different project
  const handleSelectProject = (newScanId) => {
    selectProject(newScanId);
    setSearchParams({ scanId: newScanId });
    setCustomPositions({});
    setSelectedNode(null);
    setHoveredNode(null);
  };

  // Find active scan metadata
  const activeScan = useMemo(() => {
    return scansList.find((s) => s.id === selectedScanId) || activeProject || null;
  }, [scansList, selectedScanId, activeProject]);

  // Fetch Graph Data for strictly THIS single scan
  const { data: graphData, isLoading: isGraphLoading } = useQuery({
    queryKey: ['crypto-graph', selectedScanId],
    queryFn: () => {
      if (!selectedScanId) return null;
      return getScanGraph(selectedScanId);
    },
    enabled: !!selectedScanId,
  });

  const rawNodes = graphData?.nodes || [];
  const rawEdges = graphData?.edges || [];

  // Controls & Filters
  const [layoutMode, setLayoutMode] = useState('pipeline'); // 'pipeline' | 'force' | 'radial'
  const [density, setDensity] = useState('balanced'); // 'compact' | 'balanced' | 'spacious'
  const [filterType, setFilterType] = useState('ALL');
  const [postureFilter, setPostureFilter] = useState('ALL'); // 'ALL' | 'VULNERABLE' | 'SAFE'
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);

  // Viewport transforms (optimized so 1 scan fits at 100% without zooming)
  const [zoom, setZoom] = useState(1.0);
  const [pan, setPan] = useState({ x: 40, y: 30 });
  const [isPanning, setIsPanning] = useState(false);
  const panStartRef = useRef({ x: 0, y: 0 });

  // Custom node drag positions
  const [customPositions, setCustomPositions] = useState({});
  const [draggingNodeId, setDraggingNodeId] = useState(null);
  const dragStartRef = useRef({ mouseX: 0, mouseY: 0, nodeX: 0, nodeY: 0 });

  const [copiedCypher, setCopiedCypher] = useState(false);
  const svgRef = useRef(null);

  // Density multipliers
  const densityFactor = useMemo(() => {
    if (density === 'compact') return 0.85;
    if (density === 'spacious') return 1.35;
    return 1.0;
  }, [density]);

  // Filter nodes
  const filteredNodes = useMemo(() => {
    return rawNodes.filter((n) => {
      // 1. Entity type filter
      if (filterType !== 'ALL' && n.label !== filterType) {
        if (!(filterType === 'Other' && n.label === 'Other')) return false;
      }

      // 2. Quantum posture filter
      if (postureFilter === 'VULNERABLE') {
        const isAlgo = n.label === 'Algorithm' || n.type === 'algorithm';
        const qStatus = (n.properties?.quantum_status || n.properties?.pqc_status || '').toLowerCase();
        if (isAlgo && !qStatus.includes('vuln')) return false;
      } else if (postureFilter === 'SAFE') {
        const isAlgo = n.label === 'Algorithm' || n.type === 'algorithm';
        const qStatus = (n.properties?.quantum_status || n.properties?.pqc_status || '').toLowerCase();
        if (isAlgo && !qStatus.includes('safe')) return false;
      }

      // 3. Search query
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchName = n.name?.toLowerCase().includes(q);
        const matchId = n.id?.toLowerCase().includes(q);
        const matchAlgo = n.properties?.algorithm?.toLowerCase().includes(q);
        const matchFile = n.properties?.file_path?.toLowerCase().includes(q);
        if (!matchName && !matchId && !matchAlgo && !matchFile) return false;
      }

      return true;
    });
  }, [rawNodes, filterType, postureFilter, searchQuery]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);

  // =======================================================
  // LAYOUT ENGINE: Hierarchical Pipeline (Clean Columns)
  // =======================================================
  const computePipelinePositions = useCallback(
    (nodes) => {
      const colWidth = 270 * densityFactor;
      const rowGap = 72 * densityFactor;
      const centerY = 320;

      // Group nodes by architectural tier
      const grouped = PIPELINE_COLUMNS.map((col) => ({
        ...col,
        nodes: nodes.filter(col.matches),
      }));

      // Keep only columns that have nodes in this project
      const activeCols = grouped.filter((col) => col.nodes.length > 0);
      const result = [];

      activeCols.forEach((col, colIdx) => {
        const colX = 130 + colIdx * colWidth;
        const totalHeight = (col.nodes.length - 1) * rowGap;
        const startY = Math.max(90, centerY - totalHeight / 2);

        col.nodes.forEach((n, rowIdx) => {
          result.push({
            ...n,
            x: colX,
            y: startY + rowIdx * rowGap,
            colIndex: colIdx,
            colLabel: col.label,
          });
        });
      });

      return result;
    },
    [densityFactor]
  );

  // =======================================================
  // LAYOUT ENGINE: Organic Force (Anti-collision physics)
  // =======================================================
  const computeForcePositions = useCallback(
    (nodes, edges) => {
      const centerX = 550;
      const centerY = 320;
      const count = nodes.length;
      if (count === 0) return [];

      const initialRadius = Math.max(200, count * 22) * densityFactor;
      const angleStep = (2 * Math.PI) / count;

      const simNodes = nodes.map((n, i) => ({
        ...n,
        x: centerX + initialRadius * Math.cos(i * angleStep),
        y: centerY + initialRadius * Math.sin(i * angleStep),
        vx: 0,
        vy: 0,
      }));

      const idToIdx = new Map();
      simNodes.forEach((n, idx) => idToIdx.set(n.id, idx));

      const simEdges = edges
        .filter((e) => idToIdx.has(e.source) && idToIdx.has(e.target))
        .map((e) => ({
          src: idToIdx.get(e.source),
          tgt: idToIdx.get(e.target),
        }));

      const minDist = 150 * densityFactor;
      const springLength = 200 * densityFactor;
      const kRep = 85000 * densityFactor;

      for (let iter = 0; iter < 80; iter++) {
        const cooling = Math.max(0.2, (80 - iter) / 80);

        // Repulsion
        for (let i = 0; i < count; i++) {
          for (let j = i + 1; j < count; j++) {
            const a = simNodes[i];
            const b = simNodes[j];
            let dx = b.x - a.x;
            let dy = b.y - a.y;
            let dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 1) {
              dx = (Math.random() - 0.5) * 2;
              dy = (Math.random() - 0.5) * 2;
              dist = Math.sqrt(dx * dx + dy * dy);
            }

            const rep = (kRep / (dist * dist)) * cooling;
            let fx = (dx / dist) * rep;
            let fy = (dy / dist) * rep;

            if (dist < minDist) {
              const push = ((minDist - dist) / minDist) * 40 * cooling;
              fx += (dx / dist) * push;
              fy += (dy / dist) * push;
            }

            a.vx -= fx;
            a.vy -= fy;
            b.vx += fx;
            b.vy += fy;
          }
        }

        // Springs
        for (let e = 0; e < simEdges.length; e++) {
          const edge = simEdges[e];
          const a = simNodes[edge.src];
          const b = simNodes[edge.tgt];
          let dx = b.x - a.x;
          let dy = b.y - a.y;
          let dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 1) dist = 1;

          const springForce = (dist - springLength) * 0.05 * cooling;
          a.vx += (dx / dist) * springForce;
          a.vy += (dy / dist) * springForce;
          b.vx -= (dx / dist) * springForce;
          b.vy -= (dy / dist) * springForce;
        }

        // Gravity & Damping
        for (let i = 0; i < count; i++) {
          const n = simNodes[i];
          n.vx += (centerX - n.x) * 0.015 * cooling;
          n.vy += (centerY - n.y) * 0.015 * cooling;
          n.vx *= 0.65;
          n.vy *= 0.65;
          n.x += n.vx;
          n.y += n.vy;
        }
      }

      return simNodes;
    },
    [densityFactor]
  );

  // =======================================================
  // LAYOUT ENGINE: Smart Radial
  // =======================================================
  const computeRadialPositions = useCallback(
    (nodes) => {
      const centerX = 550;
      const centerY = 320;

      const centerNodes = [];
      const ring1Nodes = [];
      const ring2Nodes = [];
      const ring3Nodes = [];

      nodes.forEach((n) => {
        if (n.label === 'Scan' || n.type === 'application') centerNodes.push(n);
        else if (n.label === 'Host' || n.label === 'File') ring1Nodes.push(n);
        else if (n.label === 'Algorithm' || n.label === 'Other') ring2Nodes.push(n);
        else ring3Nodes.push(n);
      });

      const result = [];
      centerNodes.forEach((n, idx) => {
        result.push({ ...n, x: centerX + (idx - centerNodes.length / 2) * 140, y: centerY });
      });

      const r1 = Math.max(200, (ring1Nodes.length * 55) / Math.PI) * densityFactor;
      const step1 = (2 * Math.PI) / (ring1Nodes.length || 1);
      ring1Nodes.forEach((n, idx) => {
        const angle = idx * step1 - Math.PI / 2;
        result.push({ ...n, x: centerX + r1 * Math.cos(angle), y: centerY + r1 * Math.sin(angle) });
      });

      const r2 = (r1 + Math.max(200, (ring2Nodes.length * 50) / Math.PI)) * densityFactor;
      const step2 = (2 * Math.PI) / (ring2Nodes.length || 1);
      ring2Nodes.forEach((n, idx) => {
        const angle = idx * step2 - Math.PI / 2;
        result.push({ ...n, x: centerX + r2 * Math.cos(angle), y: centerY + r2 * Math.sin(angle) });
      });

      const r3 = (r2 + Math.max(180, (ring3Nodes.length * 45) / Math.PI)) * densityFactor;
      const step3 = (2 * Math.PI) / (ring3Nodes.length || 1);
      ring3Nodes.forEach((n, idx) => {
        const angle = idx * step3 - Math.PI / 2;
        result.push({ ...n, x: centerX + r3 * Math.cos(angle), y: centerY + r3 * Math.sin(angle) });
      });

      return result;
    },
    [densityFactor]
  );

  // Compute layout positions for this single scan
  const basePositionedNodes = useMemo(() => {
    if (filteredNodes.length === 0) return [];
    if (layoutMode === 'force') return computeForcePositions(filteredNodes, rawEdges);
    if (layoutMode === 'radial') return computeRadialPositions(filteredNodes);
    return computePipelinePositions(filteredNodes);
  }, [filteredNodes, rawEdges, layoutMode, computePipelinePositions, computeForcePositions, computeRadialPositions]);

  // Combine with manual dragging
  const positionedNodes = useMemo(() => {
    return basePositionedNodes.map((n) => {
      const custom = customPositions[n.id];
      if (custom) return { ...n, x: custom.x, y: custom.y };
      return n;
    });
  }, [basePositionedNodes, customPositions]);

  const nodeMap = useMemo(() => {
    const map = new Map();
    positionedNodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [positionedNodes]);

  // Visible edges in this scan
  const visibleEdges = useMemo(() => {
    return rawEdges
      .filter((e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target))
      .map((e) => ({
        ...e,
        sourceNode: nodeMap.get(e.source),
        targetNode: nodeMap.get(e.target),
      }))
      .filter((e) => e.sourceNode && e.targetNode);
  }, [rawEdges, filteredNodeIds, nodeMap]);

  // Blast Radius Impact
  const activeFocusNode = selectedNode || hoveredNode;
  const blastRadiusInfo = useMemo(() => {
    if (!activeFocusNode) {
      return { connectedIds: new Set(), connectedEdges: new Set(), incomingCount: 0, outgoingCount: 0, impactCount: 0 };
    }

    const connectedIds = new Set([activeFocusNode.id]);
    const connectedEdges = new Set();
    let incomingCount = 0;
    let outgoingCount = 0;

    visibleEdges.forEach((e) => {
      if (e.source === activeFocusNode.id) {
        connectedIds.add(e.target);
        connectedEdges.add(e);
        outgoingCount++;
      } else if (e.target === activeFocusNode.id) {
        connectedIds.add(e.source);
        connectedEdges.add(e);
        incomingCount++;
      }
    });

    return {
      connectedIds,
      connectedEdges,
      incomingCount,
      outgoingCount,
      impactCount: Math.max(0, connectedIds.size - 1),
    };
  }, [activeFocusNode, visibleEdges]);

  // Color mapper
  const getNodeColor = (node) => {
    if (node.label === 'Algorithm' || node.type === 'algorithm') {
      const status = (node.properties?.quantum_status || node.properties?.pqc_status || '').toLowerCase();
      if (status.includes('safe')) return '#10B981';
      if (status.includes('margin') || status.includes('transitional')) return '#F59E0B';
      return '#EF4444';
    }
    if (node.label === 'File' || node.type === 'component') return '#00E5FF';
    if (node.label === 'Data' || node.type === 'data_asset') return '#C084FC';
    if (node.label === 'Host' || node.type === 'endpoint') return '#38BDF8';
    if (node.label === 'Scan' || node.type === 'application') return '#818CF8';
    return '#94A3B8';
  };

  const getNodeSublabel = (node) => {
    if (node.label === 'Algorithm' || node.type === 'algorithm') {
      const status = (node.properties?.quantum_status || node.properties?.pqc_status || '').toLowerCase();
      if (status.includes('safe')) return 'QUANTUM SAFE';
      if (status.includes('margin') || status.includes('transitional')) return 'REDUCED MARGIN';
      return 'VULNERABLE';
    }
    if (node.label === 'File' || node.type === 'component') return 'SOURCE FILE';
    if (node.label === 'Data' || node.type === 'data_asset') return `${node.properties?.sensitivity || 'SENSITIVE'} DATA`;
    if (node.label === 'Host' || node.type === 'endpoint') return 'NETWORK HOST';
    if (node.label === 'Scan' || node.type === 'application') return 'TARGET APP';
    return 'DEPENDENCY';
  };

  // Auto-Fit Viewport so the single scan fits immediately on screen
  const handleFitView = useCallback(() => {
    if (positionedNodes.length === 0 || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const width = rect.width || 1000;
    const height = rect.height || 620;

    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;

    positionedNodes.forEach((n) => {
      if (n.x < minX) minX = n.x;
      if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.y > maxY) maxY = n.y;
    });

    const graphW = Math.max(100, maxX - minX + 240);
    const graphH = Math.max(100, maxY - minY + 140);
    const fitZoom = Math.min(1.15, Math.max(0.45, Math.min((width - 40) / graphW, (height - 40) / graphH)));
    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;

    setZoom(Number(fitZoom.toFixed(2)));
    setPan({
      x: Math.round(width / 2 - centerX * fitZoom),
      y: Math.round(height / 2 - centerY * fitZoom),
    });
  }, [positionedNodes]);

  // Fit automatically whenever a scan is loaded
  useEffect(() => {
    if (positionedNodes.length > 0) {
      const timer = setTimeout(handleFitView, 100);
      return () => clearTimeout(timer);
    }
  }, [selectedScanId, layoutMode]);

  // Canvas pan handlers
  const handleCanvasMouseDown = (e) => {
    if (e.target.tagName === 'svg' || e.target.id === 'canvas-bg') {
      setIsPanning(true);
      panStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
    }
  };

  // Node drag handlers
  const handleNodeMouseDown = (e, node) => {
    e.stopPropagation();
    setDraggingNodeId(node.id);
    dragStartRef.current = {
      mouseX: e.clientX,
      mouseY: e.clientY,
      nodeX: node.x,
      nodeY: node.y,
    };
  };

  const handleMouseMove = (e) => {
    if (draggingNodeId) {
      const dx = (e.clientX - dragStartRef.current.mouseX) / zoom;
      const dy = (e.clientY - dragStartRef.current.mouseY) / zoom;
      setCustomPositions((prev) => ({
        ...prev,
        [draggingNodeId]: {
          x: Math.round(dragStartRef.current.nodeX + dx),
          y: Math.round(dragStartRef.current.nodeY + dy),
        },
      }));
    } else if (isPanning) {
      setPan({
        x: e.clientX - panStartRef.current.x,
        y: e.clientY - panStartRef.current.y,
      });
    }
  };

  const handleMouseUp = () => {
    setDraggingNodeId(null);
    setIsPanning(false);
  };

  const handleWheel = (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.08 : 0.92;
    setZoom((z) => Math.min(2.2, Math.max(0.35, Number((z * factor).toFixed(2)))));
  };

  const copyCypherQuery = () => {
    const query = `MATCH (f:File)-[r:USES_ALGORITHM]->(a:Algorithm)
WHERE a.quantum_status = 'vulnerable'
OPTIONAL MATCH (a)-[:PROTECTS_DATA]->(d:Data)
RETURN f.name, a.name, d.name LIMIT 25;`;
    navigator.clipboard.writeText(query);
    setCopiedCypher(true);
    toast.success('Sample Cypher query copied!');
    setTimeout(() => setCopiedCypher(false), 2000);
  };

  const handleExportSVG = () => {
    if (!svgRef.current) return;
    const serializer = new XMLSerializer();
    const source = serializer.serializeToString(svgRef.current);
    const blob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `topology-${activeScan?.target?.replace(/[^a-zA-Z0-9_-]/g, '_') || 'scan'}.svg`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Exported clean vector SVG graph!');
  };

  return (
    <div className="space-y-5 animate-fade-in select-none">
      {/* Top Project Selector Bar: Prominently choose which single project to inspect */}
      <div className="glass-card p-4 border border-cyan-500/20 bg-gradient-to-r from-navy-950 via-navy-900 to-navy-950 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Active Project Details */}
          <div className="flex items-start sm:items-center gap-3.5">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-400/20 text-cyan-400">
              <FolderGit2 className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
                  Target Project
                </span>
                {activeScan && (
                  <span className="text-xs text-gray-400 font-mono">
                    Scanned on {new Date(activeScan.created_at).toLocaleDateString()} at{' '}
                    {new Date(activeScan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                )}
              </div>
              <h1 className="text-lg font-bold text-white font-mono mt-0.5 flex items-center gap-2">
                <span>{activeScan?.target || 'Select a Scan Target'}</span>
                {activeScan?.vulnerable_count > 0 ? (
                  <span className="text-xs font-sans px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1 font-semibold">
                    <ShieldAlert className="w-3 h-3" />
                    {activeScan.vulnerable_count} Vulnerabilities
                  </span>
                ) : (
                  <span className="text-xs font-sans px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 font-semibold">
                    <CheckCircle2 className="w-3 h-3" />
                    Quantum-Safe
                  </span>
                )}
              </h1>
            </div>
          </div>

          {/* Project Switcher Dropdown */}
          <div className="flex items-center gap-3">
            <div className="flex flex-col sm:flex-row sm:items-center gap-2">
              <label className="text-xs font-semibold text-gray-400 whitespace-nowrap">Switch Project / Scan:</label>
              <div className="relative">
                <select
                  value={selectedScanId}
                  onChange={(e) => handleSelectProject(e.target.value)}
                  className="bg-navy-900 border border-cyan-500/30 text-cyan-200 rounded-lg px-3 py-1.5 text-xs font-medium focus:outline-none focus:border-cyan-400 pr-8 appearance-none cursor-pointer min-w-[240px]"
                >
                  {scansList.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target} ({new Date(s.created_at).toLocaleDateString()} • {s.vulnerable_count || 0} vuln)
                    </option>
                  ))}
                </select>
                <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2.5 text-cyan-400 text-xs">
                  ▼
                </div>
              </div>
            </div>

            <button
              onClick={openHistory}
              className="text-xs py-1.5 px-3 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-400/30 text-cyan-300 transition-all flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
              title="Open Project History Drawer"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              <span>Project History</span>
            </button>

            {activeScan && (
              <Link
                to={`/scan/${activeScan.id}`}
                className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5 whitespace-nowrap"
              >
                <span>Scan Telemetry</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            )}
          </div>
        </div>
      </div>

      {/* Control Strip: Layout Selector, Density, PQC Filters, Search */}
      <div className="glass-card p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
        {/* Layout Modes */}
        <div className="flex items-center gap-1.5 bg-navy-950/80 p-1 rounded-lg border border-white/10">
          <span className="text-[10px] text-gray-400 font-semibold uppercase px-2">Layout:</span>
          {[
            { id: 'pipeline', label: 'Pipeline DAG', icon: Layers },
            { id: 'force', label: 'Organic Force', icon: Compass },
            { id: 'radial', label: 'Concentric', icon: Network },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => {
                setLayoutMode(id);
                setCustomPositions({});
              }}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-all flex items-center gap-1.5 ${
                layoutMode === id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 shadow-glow-cyan'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
              }`}
            >
              <Icon className="w-3 h-3" />
              <span>{label}</span>
            </button>
          ))}
        </div>

        {/* Spacing / Density Control */}
        <div className="flex items-center gap-1.5 bg-navy-950/80 p-1 rounded-lg border border-white/10">
          <span className="text-[10px] text-gray-400 font-semibold uppercase px-2">Density:</span>
          {[
            { id: 'compact', label: 'Compact' },
            { id: 'balanced', label: 'Standard' },
            { id: 'spacious', label: 'Spacious' },
          ].map(({ id, label }) => (
            <button
              key={id}
              onClick={() => {
                setDensity(id);
                setCustomPositions({});
              }}
              className={`px-2.5 py-0.5 rounded text-[11px] font-medium transition-all ${
                density === id ? 'bg-white/15 text-white font-semibold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Quantum Vulnerability Filter */}
        <div className="flex items-center gap-1.5 bg-navy-950/80 p-1 rounded-lg border border-white/10">
          <span className="text-[10px] text-gray-400 font-semibold uppercase px-2">Filter:</span>
          <button
            onClick={() => setPostureFilter('ALL')}
            className={`px-2 py-0.5 rounded text-[11px] font-medium ${
              postureFilter === 'ALL' ? 'bg-white/15 text-white' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            All
          </button>
          <button
            onClick={() => setPostureFilter('VULNERABLE')}
            className={`px-2 py-0.5 rounded text-[11px] font-medium flex items-center gap-1 ${
              postureFilter === 'VULNERABLE'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'text-rose-400 hover:text-rose-300'
            }`}
          >
            <ShieldAlert className="w-3 h-3" />
            <span>Vulnerable Only</span>
          </button>
          <button
            onClick={() => setPostureFilter('SAFE')}
            className={`px-2 py-0.5 rounded text-[11px] font-medium flex items-center gap-1 ${
              postureFilter === 'SAFE'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                : 'text-emerald-400 hover:text-emerald-300'
            }`}
          >
            <ShieldCheck className="w-3 h-3" />
            <span>Quantum-Safe</span>
          </button>
        </div>

        {/* Search */}
        <div className="relative w-52">
          <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search this project..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-navy-900 border border-white/10 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400/50"
          />
        </div>

        {/* Export & Auto-Fit Tools */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleExportSVG}
            className="btn-secondary text-xs py-1.5 px-2.5 flex items-center gap-1"
            title="Export SVG vector file"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Export</span>
          </button>
          <button
            onClick={copyCypherQuery}
            className="btn-secondary text-xs py-1.5 px-2.5 flex items-center gap-1"
            title="Copy Cypher query"
          >
            {copiedCypher ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Terminal className="w-3.5 h-3.5 text-purple-400" />}
            <span className="hidden sm:inline">Cypher</span>
          </button>
          <div className="flex items-center bg-navy-900 border border-white/10 rounded-lg p-0.5">
            <button
              onClick={handleFitView}
              className="p-1 hover:bg-white/10 rounded text-cyan-400"
              title="Auto-Fit to Screen"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => {
                setZoom(1.0);
                setPan({ x: 40, y: 30 });
                setCustomPositions({});
              }}
              className="p-1 hover:bg-white/10 rounded text-amber-400"
              title="Reset View (100%)"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas & Inspector Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
        {/* SVG Graph Viewport */}
        <div className="lg:col-span-3 glass-card h-[640px] relative overflow-hidden border border-white/10 flex flex-col shadow-2xl">
          {isGraphLoading || isScansLoading ? (
            <div className="flex-1 flex flex-col items-center justify-center text-gray-400">
              <div className="animate-spin inline-block w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mb-3" />
              <p className="text-xs font-medium text-cyan-300">Rendering project cryptographic topology...</p>
              <p className="text-[11px] text-gray-500 mt-1">Isolating findings for {activeScan?.target || 'selected project'}</p>
            </div>
          ) : positionedNodes.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center text-gray-500 p-8 text-center">
              <Network className="w-12 h-12 text-gray-600 mb-3" />
              <p className="text-sm font-semibold text-gray-300">No Cryptographic Assets in this Project</p>
              <p className="text-xs text-gray-500 mt-1 max-w-sm">
                This project has no cryptographic findings matching active filters, or you haven't run a scan yet.
              </p>
              <Link to="/scan/new" className="btn-primary text-xs mt-4 py-2 px-4 inline-flex items-center gap-1.5">
                <span>Start New Scan</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          ) : (
            <svg
              ref={svgRef}
              className={`w-full h-full select-none ${
                draggingNodeId ? 'cursor-grabbing' : isPanning ? 'cursor-grabbing' : 'cursor-grab'
              }`}
              onMouseDown={handleCanvasMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onWheel={handleWheel}
            >
              {/* Background Grid Pattern */}
              <defs>
                <pattern id="proj-grid" width="36" height="36" patternUnits="userSpaceOnUse">
                  <path d="M 36 0 L 0 0 0 36" fill="none" stroke="rgba(255, 255, 255, 0.025)" strokeWidth="1" />
                </pattern>
                <marker id="arrow-def" markerWidth="8" markerHeight="6" refX="10" refY="3" orient="auto">
                  <polygon points="0 0, 8 3, 0 6" fill="#64748B" opacity="0.75" />
                </marker>
                <marker id="arrow-hi" markerWidth="9" markerHeight="6" refX="10" refY="3" orient="auto">
                  <polygon points="0 0, 9 3, 0 6" fill="#00E5FF" opacity="0.95" />
                </marker>
                <marker id="arrow-danger" markerWidth="9" markerHeight="6" refX="10" refY="3" orient="auto">
                  <polygon points="0 0, 9 3, 0 6" fill="#EF4444" opacity="0.95" />
                </marker>
              </defs>

              <rect id="canvas-bg" width="100%" height="100%" fill="#060A14" />
              <rect width="100%" height="100%" fill="url(#proj-grid)" pointerEvents="none" />

              {/* Transformable Graph Scene */}
              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                {/* Column Swimlane Headers in Pipeline Mode */}
                {layoutMode === 'pipeline' && (
                  <g className="pipeline-headers pointer-events-none">
                    {PIPELINE_COLUMNS.map((col, idx) => {
                      const colNodes = positionedNodes.filter((n) => n.colIndex === idx);
                      if (colNodes.length === 0) return null;
                      const colX = colNodes[0].x;
                      const minY = Math.min(...colNodes.map((n) => n.y)) - 50;

                      return (
                        <g key={col.key} transform={`translate(${colX}, ${minY})`}>
                          <rect
                            x={-80}
                            y={-10}
                            width={160}
                            height={24}
                            rx={5}
                            fill="#0A1124"
                            stroke="rgba(255, 255, 255, 0.08)"
                            strokeWidth="1"
                          />
                          <text
                            textAnchor="middle"
                            y={4}
                            fill="#38BDF8"
                            fontSize="9.5"
                            fontWeight="700"
                            letterSpacing="0.8"
                            className="font-mono uppercase"
                          >
                            {col.label} ({colNodes.length})
                          </text>
                        </g>
                      );
                    })}
                  </g>
                )}

                {/* Edges Layer */}
                <g className="edges-layer">
                  {visibleEdges.map((e, idx) => {
                    const isHighlighted = activeFocusNode && blastRadiusInfo.connectedEdges.has(e);
                    const isDimmed = activeFocusNode && !isHighlighted;
                    const isDanger =
                      e.targetNode.properties?.quantum_status === 'vulnerable' ||
                      e.sourceNode.properties?.quantum_status === 'vulnerable';

                    let pathD = '';
                    let midX = 0;
                    let midY = 0;

                    if (layoutMode === 'pipeline') {
                      const srcX = e.sourceNode.x + 85;
                      const srcY = e.sourceNode.y;
                      const tgtX = e.targetNode.x - 85;
                      const tgtY = e.targetNode.y;
                      const dx = tgtX - srcX;
                      const curveOffset = Math.max(35, dx * 0.45);

                      pathD = `M ${srcX} ${srcY} C ${srcX + curveOffset} ${srcY}, ${tgtX - curveOffset} ${tgtY}, ${tgtX} ${tgtY}`;
                      midX = (srcX + tgtX) / 2;
                      midY = (srcY + tgtY) / 2;
                    } else {
                      const srcX = e.sourceNode.x;
                      const srcY = e.sourceNode.y;
                      const tgtX = e.targetNode.x;
                      const tgtY = e.targetNode.y;

                      midX = (srcX + tgtX) / 2;
                      midY = (srcY + tgtY) / 2;
                      pathD = `M ${srcX} ${srcY} Q ${midX} ${midY - 12}, ${tgtX} ${tgtY}`;
                    }

                    const strokeColor = isHighlighted
                      ? isDanger
                        ? '#EF4444'
                        : '#00E5FF'
                      : isDanger
                      ? 'rgba(239, 68, 68, 0.45)'
                      : 'rgba(100, 116, 139, 0.35)';

                    return (
                      <g
                        key={`edge-${e.id || idx}`}
                        opacity={isDimmed ? 0.08 : 0.85}
                        className="transition-opacity duration-200"
                      >
                        <path
                          d={pathD}
                          fill="none"
                          stroke={strokeColor}
                          strokeWidth={isHighlighted ? 2.5 : 1.3}
                          strokeDasharray={e.relationship === 'PROTECTS_DATA' ? '4,4' : 'none'}
                          markerEnd={
                            isHighlighted
                              ? isDanger
                                ? 'url(#arrow-danger)'
                                : 'url(#arrow-hi)'
                              : isDanger
                              ? 'url(#arrow-danger)'
                              : 'url(#arrow-def)'
                          }
                        />

                        {/* Edge Label Pill */}
                        <g transform={`translate(${midX}, ${midY})`} className="pointer-events-none">
                          <rect
                            x={-26}
                            y={-6.5}
                            width={52}
                            height={13}
                            rx={3}
                            fill="#070D1E"
                            stroke={isHighlighted ? strokeColor : 'rgba(255, 255, 255, 0.08)'}
                            strokeWidth="0.8"
                          />
                          <text
                            textAnchor="middle"
                            y={3}
                            fill={isHighlighted ? '#FFFFFF' : '#94A3B8'}
                            fontSize="7"
                            fontWeight="600"
                            className="font-mono uppercase tracking-tight"
                          >
                            {e.relationship?.replace(/_/g, ' ') || 'LINKS'}
                          </text>
                        </g>
                      </g>
                    );
                  })}
                </g>

                {/* Nodes Layer: Crisp, solid-backdrop cards */}
                <g className="nodes-layer">
                  {positionedNodes.map((n) => {
                    const isSelected = selectedNode?.id === n.id;
                    const isHovered = hoveredNode?.id === n.id;
                    const isFocus = isSelected || isHovered;
                    const isInBlastRadius = activeFocusNode && blastRadiusInfo.connectedIds.has(n.id);
                    const isDimmed = activeFocusNode && !isInBlastRadius;
                    const color = getNodeColor(n);
                    const subLabel = getNodeSublabel(n);
                    const isAlgo = n.label === 'Algorithm' || n.type === 'algorithm';
                    const isVulnerable = isAlgo && subLabel === 'VULNERABLE';

                    const cardW = 170;
                    const cardH = 44;
                    const halfW = cardW / 2;
                    const halfH = cardH / 2;

                    const displayName =
                      n.name && n.name.length > 17 ? `${n.name.substring(0, 15)}...` : n.name || n.id;

                    return (
                      <g
                        key={`node-${n.id}`}
                        transform={`translate(${n.x}, ${n.y})`}
                        onClick={() => setSelectedNode(n)}
                        onMouseEnter={() => setHoveredNode(n)}
                        onMouseLeave={() => setHoveredNode(null)}
                        onMouseDown={(e) => handleNodeMouseDown(e, n)}
                        opacity={isDimmed ? 0.15 : 1}
                        className="cursor-pointer group"
                        style={{ transition: draggingNodeId === n.id ? 'none' : 'opacity 0.2s ease' }}
                      >
                        {/* Outer Focus Ring */}
                        {(isFocus || isInBlastRadius) && (
                          <rect
                            x={-halfW - 2.5}
                            y={-halfH - 2.5}
                            width={cardW + 5}
                            height={cardH + 5}
                            rx={9}
                            fill="none"
                            stroke={color}
                            strokeWidth={isSelected ? 2.8 : 1.8}
                            opacity={0.8}
                          />
                        )}

                        {/* Solid Card Fill */}
                        <rect
                          x={-halfW}
                          y={-halfH}
                          width={cardW}
                          height={cardH}
                          rx={7}
                          fill="#090E1F"
                          stroke={color}
                          strokeWidth={isFocus ? 2.0 : 1.2}
                        />

                        {/* Left Color Accent Bar */}
                        <rect x={-halfW} y={-halfH} width={4} height={cardH} rx={1.5} fill={color} />

                        {/* Glyph Circle */}
                        <circle
                          cx={-halfW + 18}
                          cy={0}
                          r={10}
                          fill={color}
                          fillOpacity={0.16}
                          stroke={color}
                          strokeWidth={1}
                        />

                        {isAlgo ? (
                          <rect x={-halfW + 14} y={-3.5} width={8} height={7} rx={1.5} fill={color} />
                        ) : n.label === 'File' ? (
                          <path
                            d={`M ${-halfW + 15} -5 L ${-halfW + 20} -5 L ${-halfW + 22} -2 L ${-halfW + 22} 5 L ${-halfW + 15} 5 Z`}
                            fill={color}
                          />
                        ) : n.label === 'Data' ? (
                          <ellipse cx={-halfW + 18} cy={0} rx={4.5} ry={2.5} fill={color} />
                        ) : (
                          <circle cx={-halfW + 18} cy={0} r={3.5} fill={color} />
                        )}

                        {/* Name */}
                        <text
                          x={-halfW + 34}
                          y={-3}
                          fill="#F8FAFC"
                          fontSize="10.5"
                          fontWeight={isFocus ? '700' : '600'}
                          className="font-sans pointer-events-none"
                        >
                          {displayName}
                        </text>

                        {/* Subtitle Badge */}
                        <g transform={`translate(${-halfW + 34}, 5.5)`} className="pointer-events-none">
                          <rect
                            x={0}
                            y={0}
                            width={subLabel.length * 5.8 + 8}
                            height={12}
                            rx={2}
                            fill={color}
                            fillOpacity={0.18}
                          />
                          <text
                            x={4}
                            y={8.5}
                            fill={color}
                            fontSize="7.5"
                            fontWeight="700"
                            className="font-mono uppercase tracking-tight"
                          >
                            {subLabel}
                          </text>
                        </g>

                        {/* Vulnerable Red Indicator Dot */}
                        {isVulnerable && (
                          <circle cx={halfW - 10} cy={-halfH + 10} r={3} fill="#EF4444" className="animate-pulse" />
                        )}
                      </g>
                    );
                  })}
                </g>
              </g>
            </svg>
          )}

          {/* Bottom Telemetry Bar */}
          <div className="p-2.5 border-t border-white/10 bg-navy-950/90 flex flex-wrap items-center justify-between text-xs text-gray-400 gap-2">
            <div className="flex items-center gap-3.5 flex-wrap text-[11px]">
              <span className="flex items-center gap-1.5 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" /> Vulnerable Algo
              </span>
              <span className="flex items-center gap-1.5 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block" /> Quantum Safe
              </span>
              <span className="flex items-center gap-1.5 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" /> Source File
              </span>
              <span className="flex items-center gap-1.5 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" /> Sensitive Data
              </span>
            </div>
            <div className="font-mono text-[11px] text-gray-400">
              Project Findings: <span className="text-white font-semibold">{positionedNodes.length}</span> nodes •{' '}
              <span className="text-white font-semibold">{visibleEdges.length}</span> dependencies
            </div>
          </div>
        </div>

        {/* Node Inspector Sidebar */}
        <div className="glass-card p-5 flex flex-col justify-between border border-white/10 h-[640px] overflow-y-auto">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5" />
                <span>Entity Inspector</span>
              </h2>
              {selectedNode && (
                <button onClick={() => setSelectedNode(null)} className="text-xs text-gray-400 hover:text-white">
                  Deselect
                </button>
              )}
            </div>

            {selectedNode ? (
              <div className="space-y-4 text-xs">
                {/* Entity Label & Type */}
                <div>
                  <span className="text-[10px] text-gray-400 uppercase font-semibold">Entity Type</span>
                  <div className="text-sm font-bold text-white flex items-center gap-2 mt-0.5">
                    <span
                      className="w-2.5 h-2.5 rounded-full inline-block"
                      style={{ backgroundColor: getNodeColor(selectedNode) }}
                    />
                    <span>{selectedNode.label}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/10 text-gray-300">
                      {selectedNode.type}
                    </span>
                  </div>
                </div>

                {/* Entity Identifier */}
                <div>
                  <span className="text-[10px] text-gray-400 uppercase font-semibold">Identifier</span>
                  <div className="text-xs font-mono text-cyan-300 break-all bg-navy-950/80 p-2.5 rounded-lg border border-white/5 mt-1 font-semibold">
                    {selectedNode.name || selectedNode.id}
                  </div>
                </div>

                {/* Blast Radius Card */}
                <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/25 space-y-2">
                  <div className="flex items-center justify-between text-amber-300 font-semibold">
                    <span className="flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>Project Blast Radius</span>
                    </span>
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-amber-500/20">
                      {blastRadiusInfo.impactCount} Connected
                    </span>
                  </div>
                  <p className="text-[11px] text-gray-300 leading-relaxed">
                    Direct cryptographic dependency linkages connecting this entity inside {activeScan?.target}.
                  </p>
                  <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-[10px]">
                    <div className="bg-navy-950/60 p-1.5 rounded border border-white/5">
                      <span className="text-gray-400 block">Incoming:</span>
                      <span className="text-white font-bold">{blastRadiusInfo.incomingCount}</span>
                    </div>
                    <div className="bg-navy-950/60 p-1.5 rounded border border-white/5">
                      <span className="text-gray-400 block">Outgoing:</span>
                      <span className="text-white font-bold">{blastRadiusInfo.outgoingCount}</span>
                    </div>
                  </div>
                </div>

                {/* Quantum Risk Posture Assessment */}
                {selectedNode.label === 'Algorithm' && (
                  <div className="p-3 rounded-lg bg-navy-950 border border-white/10 space-y-2">
                    <span className="text-[10px] text-gray-400 uppercase font-semibold block">
                      Quantum Risk Assessment
                    </span>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300 font-medium">Status:</span>
                      <span className="font-bold uppercase text-xs" style={{ color: getNodeColor(selectedNode) }}>
                        {selectedNode.properties?.quantum_status || 'Unknown'}
                      </span>
                    </div>
                    {selectedNode.properties?.risk_score !== undefined && (
                      <div className="flex items-center justify-between">
                        <span className="text-gray-300 font-medium">Risk Score:</span>
                        <span className="font-mono text-rose-400 font-bold">
                          {selectedNode.properties.risk_score} / 100
                        </span>
                      </div>
                    )}
                    <div className="text-[11px] text-gray-400 border-t border-white/5 pt-2">
                      {selectedNode.properties?.quantum_status === 'vulnerable' ? (
                        <p className="text-rose-300/90">
                          ⚠️ Vulnerable to quantum polynomial-time decryption. Replace with NIST FIPS 203 (ML-KEM) or FIPS 204 (ML-DSA).
                        </p>
                      ) : (
                        <p className="text-emerald-300/90">
                          🛡️ Meets Post-Quantum Cryptography resistance standards.
                        </p>
                      )}
                    </div>
                  </div>
                )}

                {/* Normalized Properties Table */}
                <div>
                  <span className="text-[10px] text-gray-400 uppercase font-semibold block mb-1">
                    Normalized Properties
                  </span>
                  <div className="bg-navy-950 p-2.5 rounded-lg border border-white/5 space-y-1.5 font-mono text-[11px]">
                    {Object.entries(selectedNode.properties || {}).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2 border-b border-white/[0.03] pb-1">
                        <span className="text-gray-400">{k}:</span>
                        <span className="text-gray-200 text-right truncate max-w-[140px]" title={String(v)}>
                          {String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Link to Inventory */}
                <Link
                  to={`/inventory?scan_id=${selectedScanId}`}
                  className="btn-secondary w-full text-xs py-2 flex items-center justify-center gap-1.5 text-center mt-2"
                >
                  <span>View in Project Inventory</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            ) : (
              <div className="text-center py-20 text-gray-500 space-y-3">
                <Network className="w-10 h-10 text-gray-600 mx-auto" />
                <p className="text-xs font-semibold text-gray-300">Select Any Entity to Inspect</p>
                <p className="text-[11px] text-gray-500 max-w-xs mx-auto leading-relaxed">
                  Click any card to trace its cryptographic attack paths, audit blast radius, or drag cards to rearrange.
                </p>
                <div className="pt-2">
                  <span className="text-[10px] text-cyan-400/80 bg-cyan-400/10 px-2.5 py-1 rounded-full font-mono">
                    💡 Single-Project Isolation Active
                  </span>
                </div>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-white/5 text-[10px] text-gray-500 font-mono text-center flex items-center justify-between">
            <span>CipherSight Topology</span>
            <span className="text-cyan-400">1 Scan Isolated</span>
          </div>
        </div>
      </div>
    </div>
  );
}
