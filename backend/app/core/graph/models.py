"""
Data structures for the Cryptographic Topology and Dependency Graph.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GraphNode:
    """Represents a node in the cryptographic dependency graph."""
    id: str
    label: str
    type: str  # application | service | library | algorithm | certificate | endpoint | data_asset
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.type,
            "properties": self.properties,
        }


@dataclass
class GraphEdge:
    """Represents a relationship edge between two cryptographic nodes."""
    id: str
    source: str
    target: str
    relationship: str  # USES_ALGORITHM | LINKS_LIBRARY | PROTECTS_DATA | EXPOSES_ENDPOINT | CALLS
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "properties": self.properties,
        }


@dataclass
class GraphData:
    """Full cryptographic dependency graph with nodes, edges, and summary metrics."""
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    critical_chains: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "summary": self.summary,
            "critical_chains": self.critical_chains,
        }
