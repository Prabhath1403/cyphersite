import React, { useState, useMemo, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
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
} from 'lucide-react';
import { getGraph } from '../api/client';
import toast from 'react-hot-toast';
import PQCBadge from '../components/PQCBadge';

export default function DependencyGraph() {
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [filterType, setFilterType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [copiedCypher, setCopiedCypher] = useState(false);

  const svgRef = useRef(null);

  const { data: graphData, isLoading } = useQuery({
    queryKey: ['crypto-graph'],
    queryFn: () => getGraph({ limit: 150 }),
  });

  const nodes = graphData?.nodes || [];
  const edges = graphData?.edges || [];

  // Filter nodes based on filterType and search
  const filteredNodes = useMemo(() => {
    return nodes.filter((n) => {
      if (filterType !== 'ALL' && n.label !== filterType) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchName = n.name?.toLowerCase().includes(q);
        const matchId = n.id?.toLowerCase().includes(q);
        const matchAlgo = n.properties?.algorithm?.toLowerCase().includes(q);
        if (!matchName && !matchId && !matchAlgo) return false;
      }
      return true;
    });
  }, [nodes, filterType, searchQuery]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);

  // Compute circular / force-like positions for SVG layout
  const positionedNodes = useMemo(() => {
    const total = filteredNodes.length;
    if (total === 0) return [];

    const width = 1000;
    const height = 650;
    const centerX = width / 2;
    const centerY = height / 2;

    const layers = {
      Scan: { radius: 0, nodes: [] },
      File: { radius: 180, nodes: [] },
      Host: { radius: 220, nodes: [] },
      Algorithm: { radius: 320, nodes: [] },
      Data: { radius: 410, nodes: [] },
      Other: { radius: 360, nodes: [] },
    };

    filteredNodes.forEach((n) => {
      const lbl = layers[n.label] ? n.label : 'Other';
      layers[lbl].nodes.push(n);
    });

    const result = [];

    Object.entries(layers).forEach(([lbl, info]) => {
      const count = info.nodes.length;
      if (count === 0) return;

      if (info.radius === 0) {
        info.nodes.forEach((n, idx) => {
          result.push({
            ...n,
            x: centerX + (idx - count / 2) * 50,
            y: centerY,
          });
        });
      } else {
        const angleStep = (2 * Math.PI) / count;
        info.nodes.forEach((n, idx) => {
          const angle = idx * angleStep;
          result.push({
            ...n,
            x: centerX + info.radius * Math.cos(angle),
            y: centerY + info.radius * Math.sin(angle),
          });
        });
      }
    });

    return result;
  }, [filteredNodes]);

  const nodeMap = useMemo(() => {
    const map = new Map();
    positionedNodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [positionedNodes]);

  const visibleEdges = useMemo(() => {
    return edges
      .filter((e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target))
      .map((e) => ({
        ...e,
        sourceNode: nodeMap.get(e.source),
        targetNode: nodeMap.get(e.target),
      }))
      .filter((e) => e.sourceNode && e.targetNode);
  }, [edges, filteredNodeIds, nodeMap]);

  // Calculate Blast Radius for Selected or Hovered Node
  const activeFocusNode = selectedNode || hoveredNode;
  const blastRadiusInfo = useMemo(() => {
    if (!activeFocusNode) return { connectedIds: new Set(), connectedEdges: new Set(), impactCount: 0 };

    const connectedIds = new Set([activeFocusNode.id]);
    const connectedEdges = new Set();

    visibleEdges.forEach((e) => {
      if (e.source === activeFocusNode.id) {
        connectedIds.add(e.target);
        connectedEdges.add(e);
      } else if (e.target === activeFocusNode.id) {
        connectedIds.add(e.source);
        connectedEdges.add(e);
      }
    });

    return {
      connectedIds,
      connectedEdges,
      impactCount: Math.max(0, connectedIds.size - 1),
    };
  }, [activeFocusNode, visibleEdges]);

  // Pan interaction
  const handleMouseDown = (e) => {
    if (e.target.tagName === 'svg' || e.target.id === 'canvas-bg') {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e) => {
    if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const getNodeColor = (node) => {
    if (node.label === 'Algorithm') {
      const status = (node.properties?.quantum_status || node.properties?.pqc_status || '').toLowerCase();
      if (status.includes('safe')) return '#10B981';
      if (status.includes('margin') || status.includes('hybrid')) return '#F59E0B';
      return '#F43F5E';
    }
    if (node.label === 'File') return '#00E5FF';
    if (node.label === 'Data') return '#C084FC';
    if (node.label === 'Host') return '#38BDF8';
    return '#94A3B8';
  };

  const copyCypherQuery = () => {
    const query = `MATCH (f:File)-[r:IMPLEMENTS]->(a:Algorithm {quantum_status: 'vulnerable'}) RETURN f, r, a LIMIT 50;`;
    navigator.clipboard.writeText(query);
    setCopiedCypher(true);
    toast.success('Sample Neo4j Cypher query copied!');
    setTimeout(() => setCopiedCypher(false), 2000);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-400/20">
              TOPOLOGY ENGINE
            </span>
            <span className="text-xs text-gray-400 font-mono">Neo4j Graph Schema</span>
          </div>
          <h1 className="page-header flex items-center gap-2.5">
            <Network className="w-6 h-6 text-cyan-400" />
            <span>Cryptographic Topology Graph</span>
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            End-to-end dependency mapping linking Applications → Source Files → Ciphers → Sensitive Data Assets.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={copyCypherQuery}
            className="btn-secondary text-xs py-2 px-3"
            title="Copy Neo4j Cypher query to clipboard"
          >
            {copiedCypher ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Terminal className="w-3.5 h-3.5 text-purple-400" />}
            <span>Copy Cypher Query</span>
          </button>

          {/* Zoom & Pan Navigation Control */}
          <div className="flex items-center bg-navy-900 border border-white/10 rounded-lg p-1 text-xs">
            <button
              onClick={() => setZoom((z) => Math.max(0.4, Number((z - 0.2).toFixed(1))))}
              className="p-1.5 hover:bg-white/10 rounded text-gray-300 hover:text-white"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="px-2 text-gray-300 font-mono text-[11px] min-w-[42px] text-center">
              {Math.round(zoom * 100)}%
            </span>
            <button
              onClick={() => setZoom((z) => Math.min(2.5, Number((z + 0.2).toFixed(1))))}
              className="p-1.5 hover:bg-white/10 rounded text-gray-300 hover:text-white"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
              }}
              className="p-1.5 hover:bg-white/10 rounded text-cyan-400"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Control Filter Bar */}
      <div className="glass-card p-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mr-2">
            Node Filter:
          </span>
          {[
            { id: 'ALL', label: 'All Entities', icon: Layers },
            { id: 'Algorithm', label: 'Algorithms', icon: Lock },
            { id: 'File', label: 'Source Files', icon: FileCode },
            { id: 'Data', label: 'Sensitive Data', icon: Database },
            { id: 'Host', label: 'Network Hosts', icon: Globe },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setFilterType(id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
                filterType === id
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 shadow-glow-cyan'
                  : 'bg-white/[0.03] text-gray-400 hover:text-gray-200 hover:bg-white/[0.06] border border-transparent'
              }`}
            >
              <Icon className="w-3 h-3" />
              <span>{label}</span>
            </button>
          ))}
        </div>

        <div className="relative w-64">
          <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search nodes, ciphers..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-navy-900 border border-white/10 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400/50"
          />
        </div>
      </div>

      {/* Graph Area + Inspector Sidebar */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
        {/* SVG Canvas */}
        <div className="lg:col-span-3 glass-card h-[680px] relative overflow-hidden border border-white/10 flex flex-col">
          {isLoading ? (
            <div className="flex-1 flex flex-col items-center justify-center text-gray-400">
              <div className="animate-spin inline-block w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mb-3" />
              <p className="text-xs">Traversing and compiling cryptographic topology graph...</p>
            </div>
          ) : positionedNodes.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center text-gray-500">
              <Network className="w-10 h-10 text-gray-600 mb-2" />
              <p className="text-sm font-medium text-gray-400">No graph nodes match criteria</p>
              <p className="text-xs text-gray-600 mt-1">Run a scan or adjust node filters above</p>
            </div>
          ) : (
            <svg
              ref={svgRef}
              className="w-full h-full cursor-grab active:cursor-grabbing select-none"
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
            >
              <rect id="canvas-bg" width="100%" height="100%" fill="transparent" />
              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                <defs>
                  <marker
                    id="arrowhead"
                    markerWidth="8"
                    markerHeight="6"
                    refX="22"
                    refY="3"
                    orient="auto"
                  >
                    <polygon points="0 0, 8 3, 0 6" fill="#64748B" opacity="0.6" />
                  </marker>
                  <marker
                    id="arrowhead-highlight"
                    markerWidth="8"
                    markerHeight="6"
                    refX="22"
                    refY="3"
                    orient="auto"
                  >
                    <polygon points="0 0, 8 3, 0 6" fill="#00E5FF" opacity="0.9" />
                  </marker>
                </defs>

                {/* Edges */}
                {visibleEdges.map((e, idx) => {
                  const isHighlighted = activeFocusNode && blastRadiusInfo.connectedEdges.has(e);
                  const isDimmed = activeFocusNode && !isHighlighted;

                  return (
                    <g key={idx} opacity={isDimmed ? 0.15 : 0.8} className="transition-opacity duration-200">
                      <line
                        x1={e.sourceNode.x}
                        y1={e.sourceNode.y}
                        x2={e.targetNode.x}
                        y2={e.targetNode.y}
                        stroke={isHighlighted ? '#00E5FF' : '#475569'}
                        strokeWidth={isHighlighted ? 2.5 : 1.2}
                        strokeDasharray={e.type === 'ENCRYPTS' ? '4,4' : 'none'}
                        markerEnd={isHighlighted ? 'url(#arrowhead-highlight)' : 'url(#arrowhead)'}
                      />
                      <text
                        x={(e.sourceNode.x + e.targetNode.x) / 2}
                        y={(e.sourceNode.y + e.targetNode.y) / 2 - 4}
                        fill={isHighlighted ? '#67E8F9' : '#94A3B8'}
                        fontSize="9"
                        textAnchor="middle"
                        className="font-mono select-none pointer-events-none"
                      >
                        {e.type}
                      </text>
                    </g>
                  );
                })}

                {/* Nodes */}
                {positionedNodes.map((n) => {
                  const isSelected = selectedNode?.id === n.id;
                  const isHovered = hoveredNode?.id === n.id;
                  const isFocus = isSelected || isHovered;
                  const isInBlastRadius = activeFocusNode && blastRadiusInfo.connectedIds.has(n.id);
                  const isDimmed = activeFocusNode && !isInBlastRadius;
                  const color = getNodeColor(n);

                  return (
                    <g
                      key={n.id}
                      transform={`translate(${n.x}, ${n.y})`}
                      onClick={() => setSelectedNode(n)}
                      onMouseEnter={() => setHoveredNode(n)}
                      onMouseLeave={() => setHoveredNode(null)}
                      className="cursor-pointer group"
                      opacity={isDimmed ? 0.2 : 1}
                      style={{ transition: 'opacity 0.2s ease, transform 0.2s ease' }}
                    >
                      {/* Outer Ring / Halo */}
                      <circle
                        r={isFocus ? 22 : 16}
                        fill="#08101E"
                        stroke={color}
                        strokeWidth={isFocus ? 3 : 2}
                        style={{
                          filter: isFocus || isInBlastRadius ? `drop-shadow(0 0 12px ${color})` : 'none',
                        }}
                      />
                      {/* Inner Dot */}
                      <circle r={isFocus ? 13 : 8} fill={color} opacity="0.9" />

                      {/* Label */}
                      <text
                        y={28}
                        textAnchor="middle"
                        fill="#F1F5F9"
                        fontSize="11"
                        fontWeight={isFocus ? '700' : '500'}
                        className="pointer-events-none drop-shadow"
                      >
                        {n.name?.length > 20 ? `${n.name.substring(0, 18)}...` : n.name}
                      </text>
                      <text
                        y={40}
                        textAnchor="middle"
                        fill="#64748B"
                        fontSize="9"
                        className="pointer-events-none font-mono uppercase"
                      >
                        {n.label}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          )}

          {/* Minimap Viewport Overlay */}
          <div className="absolute bottom-12 right-4 w-36 h-24 rounded-lg bg-navy-950/90 border border-white/10 p-1.5 shadow-xl hidden sm:block pointer-events-none">
            <div className="w-full h-full relative rounded border border-dashed border-white/10 overflow-hidden bg-navy-900/60">
              {positionedNodes.map((n) => (
                <div
                  key={n.id}
                  className="absolute w-1 h-1 rounded-full"
                  style={{
                    left: `${(n.x / 1000) * 100}%`,
                    top: `${(n.y / 650) * 100}%`,
                    backgroundColor: getNodeColor(n),
                  }}
                />
              ))}
              {/* Viewport Indicator */}
              <div
                className="absolute border border-cyan-400/60 bg-cyan-400/10 rounded-sm"
                style={{
                  left: `${Math.max(0, Math.min(60, 30 - pan.x / 30))}%`,
                  top: `${Math.max(0, Math.min(60, 30 - pan.y / 30))}%`,
                  width: `${Math.max(20, Math.min(80, 80 / zoom))}%`,
                  height: `${Math.max(20, Math.min(80, 80 / zoom))}%`,
                }}
              />
            </div>
          </div>

          {/* Graph Legend & Telemetry Bar */}
          <div className="p-3 border-t border-white/10 bg-navy-950/90 flex flex-wrap items-center justify-between text-xs text-gray-400 gap-2">
            <div className="flex items-center gap-4 flex-wrap text-[11px]">
              <span className="flex items-center gap-1.5 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" /> Vulnerable Algo
              </span>
              <span className="flex items-center gap-1.5 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block" /> Reduced Margin
              </span>
              <span className="flex items-center gap-1.5 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block" /> Quantum Safe
              </span>
              <span className="flex items-center gap-1.5 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" /> Source File
              </span>
              <span className="flex items-center gap-1.5 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" /> Sensitive Payload
              </span>
            </div>
            <div className="font-mono text-[11px] text-gray-400">
              Nodes: <span className="text-white font-semibold">{positionedNodes.length}</span> • Edges:{' '}
              <span className="text-white font-semibold">{visibleEdges.length}</span>
            </div>
          </div>
        </div>

        {/* Node Inspector Sidebar */}
        <div className="glass-card p-5 flex flex-col justify-between border border-white/10 h-[680px] overflow-y-auto">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5" />
                <span>Topology Inspector</span>
              </h2>
              {selectedNode && (
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-xs text-gray-400 hover:text-white"
                >
                  Deselect
                </button>
              )}
            </div>

            {selectedNode ? (
              <div className="space-y-4 text-xs">
                <div>
                  <span className="text-[10px] text-gray-400 uppercase font-semibold">Entity Type</span>
                  <div className="text-base font-bold text-white flex items-center gap-2 mt-0.5">
                    <span
                      className="w-3 h-3 rounded-full inline-block"
                      style={{ backgroundColor: getNodeColor(selectedNode) }}
                    />
                    <span>{selectedNode.label}</span>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-gray-400 uppercase font-semibold">Entity Name</span>
                  <div className="text-sm font-mono text-cyan-300 break-all bg-navy-950/80 p-2.5 rounded-lg border border-white/5 mt-1 font-semibold">
                    {selectedNode.name}
                  </div>
                </div>

                {/* Blast Radius Card */}
                <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/25 space-y-1">
                  <div className="flex items-center justify-between text-amber-300 font-semibold">
                    <span className="flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>Blast Radius</span>
                    </span>
                    <span className="font-mono text-sm">{blastRadiusInfo.impactCount} Connected</span>
                  </div>
                  <p className="text-[11px] text-gray-300">
                    Direct cryptographic dependency links with this entity across repositories, hosts, and data pipelines.
                  </p>
                </div>

                {/* Properties list */}
                <div>
                  <span className="text-[10px] text-gray-400 uppercase font-semibold block mb-1">
                    Normalized Properties
                  </span>
                  <div className="bg-navy-950 p-3 rounded-lg border border-white/5 space-y-1.5 font-mono">
                    {Object.entries(selectedNode.properties || {}).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2 border-b border-white/[0.03] pb-1">
                        <span className="text-gray-400">{k}:</span>
                        <span className="text-gray-200 text-right truncate max-w-[150px]" title={String(v)}>
                          {String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Action shortcut to inventory */}
                <Link
                  to={`/inventory`}
                  className="btn-secondary w-full text-xs py-2 flex items-center justify-center gap-1.5 text-center mt-2"
                >
                  <span>Query in Asset Inventory</span>
                  <ArrowRight className="w-3 h-3" />
                </Link>
              </div>
            ) : (
              <div className="text-center py-24 text-gray-500 space-y-2">
                <Network className="w-8 h-8 text-gray-600 mx-auto" />
                <p className="text-xs font-medium text-gray-400">Select a node to inspect</p>
                <p className="text-[11px] text-gray-600 max-w-xs mx-auto">
                  Click any node in the topology canvas to calculate blast radius, examine dependencies, and audit quantum exposure.
                </p>
              </div>
            )}
          </div>

          <div className="pt-4 border-t border-white/5 text-[10px] text-gray-400 font-mono text-center">
            CipherSight GraphEngine • Neo4j Cypher Schema
          </div>
        </div>
      </div>
    </div>
  );
}
