import React, { useState, useMemo, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getGraph } from '../api/client';
import toast from 'react-hot-toast';

export default function DependencyGraph() {
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterType, setFilterType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const svgRef = useRef(null);

  const { data: graphData, isLoading, error } = useQuery({
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

    // Group nodes by label into concentric rings
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
      if (status.includes('safe')) return '#00E676';
      if (status.includes('margin') || status.includes('hybrid')) return '#FFD600';
      return '#FF1744';
    }
    if (node.label === 'File') return '#00E5FF';
    if (node.label === 'Data') return '#C084FC';
    if (node.label === 'Host') return '#38BDF8';
    return '#94A3B8';
  };

  const copyCypherQuery = () => {
    const query = `MATCH (f:File)-[r:IMPLEMENTS]->(a:Algorithm {quantum_status: 'vulnerable'}) RETURN f, r, a LIMIT 50;`;
    navigator.clipboard.writeText(query);
    toast.success('Sample Neo4j Cypher query copied!');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <span>🕸️</span> Cryptographic Topology Graph
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Visual dependency graph tracing algorithms, call-sites, sensitive data payloads, and network endpoints.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={copyCypherQuery}
            className="px-3 py-1.5 rounded-lg text-xs font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30 hover:bg-purple-500/20 transition-colors"
          >
            📋 Copy Neo4j Cypher
          </button>
          <div className="flex items-center bg-navy-900 border border-white/10 rounded-lg p-1">
            <button
              onClick={() => setZoom((z) => Math.max(0.4, z - 0.2))}
              className="px-2 py-1 text-xs text-gray-300 hover:text-white"
            >
              -
            </button>
            <span className="text-xs px-2 text-gray-400 font-mono">{Math.round(zoom * 100)}%</span>
            <button
              onClick={() => setZoom((z) => Math.min(2.5, z + 0.2))}
              className="px-2 py-1 text-xs text-gray-300 hover:text-white"
            >
              +
            </button>
            <button
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
              }}
              className="px-2 py-1 text-xs text-cyan-400 hover:underline"
            >
              Reset
            </button>
          </div>
        </div>
      </div>

      {/* Control Filters */}
      <div className="glass-card p-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Show Nodes:</span>
          {['ALL', 'Algorithm', 'File', 'Data', 'Host'].map((type) => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                filterType === type
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                  : 'bg-white/5 text-gray-400 hover:text-gray-200'
              }`}
            >
              {type}
            </button>
          ))}
        </div>
        <div className="w-64">
          <input
            type="text"
            placeholder="Search graph nodes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full px-3 py-1 rounded-lg bg-navy-950 border border-white/10 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400/50"
          />
        </div>
      </div>

      {/* Graph Visual Area */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 glass-card h-[680px] relative overflow-hidden border border-white/10 flex flex-col">
          {isLoading ? (
            <div className="flex-1 flex items-center justify-center text-gray-400">
              <div className="animate-spin inline-block w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mr-3" />
              Rendering cryptographic graph...
            </div>
          ) : positionedNodes.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-gray-500">
              No graph nodes match criteria. Run a scan to generate graph nodes.
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
                {/* Defs for arrow markers */}
                <defs>
                  <marker
                    id="arrowhead"
                    markerWidth="8"
                    markerHeight="6"
                    refX="20"
                    refY="3"
                    orient="auto"
                  >
                    <polygon points="0 0, 8 3, 0 6" fill="#64748B" opacity="0.6" />
                  </marker>
                </defs>

                {/* Edges */}
                {visibleEdges.map((e, idx) => (
                  <g key={idx}>
                    <line
                      x1={e.sourceNode.x}
                      y1={e.sourceNode.y}
                      x2={e.targetNode.x}
                      y2={e.targetNode.y}
                      stroke="#475569"
                      strokeWidth="1.5"
                      strokeDasharray={e.type === 'ENCRYPTS' ? '4,4' : 'none'}
                      opacity="0.6"
                      markerEnd="url(#arrowhead)"
                    />
                    <text
                      x={(e.sourceNode.x + e.targetNode.x) / 2}
                      y={(e.sourceNode.y + e.targetNode.y) / 2 - 4}
                      fill="#94A3B8"
                      fontSize="9"
                      textAnchor="middle"
                      className="font-mono select-none pointer-events-none"
                    >
                      {e.type}
                    </text>
                  </g>
                ))}

                {/* Nodes */}
                {positionedNodes.map((n) => {
                  const isSelected = selectedNode?.id === n.id;
                  const color = getNodeColor(n);
                  return (
                    <g
                      key={n.id}
                      transform={`translate(${n.x}, ${n.y})`}
                      onClick={() => setSelectedNode(n)}
                      className="cursor-pointer group"
                    >
                      <circle
                        r={isSelected ? 22 : 16}
                        fill="#0A1929"
                        stroke={color}
                        strokeWidth={isSelected ? 3 : 2}
                        className="transition-all duration-200"
                        style={{ filter: isSelected ? `drop-shadow(0 0 10px ${color})` : 'none' }}
                      />
                      <circle r={isSelected ? 14 : 9} fill={color} opacity="0.8" />
                      <text
                        y={28}
                        textAnchor="middle"
                        fill="#E2E8F0"
                        fontSize="11"
                        fontWeight="500"
                        className="pointer-events-none drop-shadow"
                      >
                        {n.name?.length > 18 ? `${n.name.substring(0, 16)}...` : n.name}
                      </text>
                      <text
                        y={40}
                        textAnchor="middle"
                        fill="#64748B"
                        fontSize="9"
                        className="pointer-events-none font-mono"
                      >
                        {n.label}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          )}

          {/* Graph Legend */}
          <div className="p-3 border-t border-white/5 bg-navy-950/60 flex items-center justify-between text-[11px] text-gray-400">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" /> Vulnerable Algo</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block" /> Reduced Margin</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block" /> Quantum Safe</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" /> Source File</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" /> Sensitive Data</span>
            </div>
            <span>Nodes: {positionedNodes.length} • Edges: {visibleEdges.length}</span>
          </div>
        </div>

        {/* Node Inspector Sidebar */}
        <div className="glass-card p-5 flex flex-col justify-between border border-white/10">
          <div>
            <h2 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-3">
              Node Inspector
            </h2>
            {selectedNode ? (
              <div className="space-y-4">
                <div>
                  <div className="text-[11px] text-gray-500 uppercase tracking-wider">Node Type</div>
                  <div className="text-base font-bold text-white flex items-center gap-2">
                    <span
                      className="w-3 h-3 rounded-full inline-block"
                      style={{ backgroundColor: getNodeColor(selectedNode) }}
                    />
                    {selectedNode.label}
                  </div>
                </div>

                <div>
                  <div className="text-[11px] text-gray-500 uppercase tracking-wider">Entity Name</div>
                  <div className="text-sm font-mono text-cyan-300 break-all">{selectedNode.name}</div>
                </div>

                <div>
                  <div className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">Properties</div>
                  <div className="bg-navy-950 p-3 rounded-lg border border-white/5 space-y-1 text-xs">
                    {Object.entries(selectedNode.properties || {}).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2">
                        <span className="text-gray-400">{k}:</span>
                        <span className="text-gray-200 font-mono text-right truncate max-w-[140px]" title={String(v)}>
                          {String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">Node Identifier</div>
                  <div className="font-mono text-[11px] text-gray-400 break-all bg-navy-950 p-2 rounded">
                    {selectedNode.id}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-20 text-gray-500 text-xs">
                Click any node in the topology canvas to inspect cryptographic properties, dependencies, and risk metrics.
              </div>
            )}
          </div>

          <div className="pt-4 border-t border-white/5 text-[11px] text-gray-500">
            Powered by CipherSight GraphEngine & Neo4j Cypher schemas.
          </div>
        </div>
      </div>
    </div>
  );
}
