"""
Graph Engine — transforms cryptographic discovery findings into an actionable
dependency and attack path graph.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.graph.models import GraphNode, GraphEdge, GraphData

logger = logging.getLogger(__name__)


class GraphEngine:
    """
    Constructs topological graphs connecting Applications, Source Files,
    Libraries, Cryptographic Algorithms, and Sensitive Data assets.
    """

    @classmethod
    def build_graph(
        cls,
        findings: List[Any],
        target_name: str = "Application Target",
        scan_id: Optional[str] = None,
    ) -> GraphData:
        """
        Transform a list of findings (CryptoAsset or CryptoFindingData) into GraphData.
        """
        nodes_dict: Dict[str, GraphNode] = {}
        edges_dict: Dict[str, GraphEdge] = {}
        critical_chains: List[Dict[str, Any]] = []

        # 1. Root Application Node
        app_id = f"app:{target_name}"
        nodes_dict[app_id] = GraphNode(
            id=app_id,
            label=target_name,
            type="application",
            properties={
                "scan_id": scan_id or "",
                "target": target_name,
            },
        )

        for finding in findings:
            # Handle both ORM CryptoAsset and dataclass CryptoFindingData
            f_dict = finding.__dict__ if hasattr(finding, "__dict__") else finding

            name = f_dict.get("name") or "Finding"
            algorithm = f_dict.get("algorithm") or "Unknown"
            library = f_dict.get("library")
            file_path = f_dict.get("file_path")
            hostname = f_dict.get("hostname")
            port = f_dict.get("port")
            sensitivity = f_dict.get("sensitivity") or "UNKNOWN"
            pqc_status = f_dict.get("pqc_status") or "UNKNOWN"
            quantum_status = f_dict.get("quantum_status") or "unknown"
            risk_score = float(f_dict.get("risk_score") or 0.0)
            risk_level = f_dict.get("risk_level") or "LOW"
            primitive = f_dict.get("primitive") or "unknown"
            usage = f_dict.get("usage") or "cryptographic_operation"

            # 2. Algorithm Node
            algo_id = f"algo:{algorithm.lower()}"
            if algo_id not in nodes_dict:
                nodes_dict[algo_id] = GraphNode(
                    id=algo_id,
                    label=algorithm,
                    type="algorithm",
                    properties={
                        "primitive": primitive,
                        "pqc_status": pqc_status,
                        "quantum_status": quantum_status,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                    },
                )

            # 3. Source File / Container / Binary Component Node
            component_id = app_id
            if file_path:
                component_id = f"file:{file_path}"
                if component_id not in nodes_dict:
                    nodes_dict[component_id] = GraphNode(
                        id=component_id,
                        label=file_path.split("/")[-1],
                        type="component",
                        properties={"file_path": file_path},
                    )
                    # Link app -> file
                    edge_id = f"edge:{app_id}->{component_id}"
                    edges_dict[edge_id] = GraphEdge(
                        id=edge_id,
                        source=app_id,
                        target=component_id,
                        relationship="CONTAINS_COMPONENT",
                    )

            # Link component -> algorithm
            edge_algo_id = f"edge:{component_id}->{algo_id}:{usage}"
            if edge_algo_id not in edges_dict:
                edges_dict[edge_algo_id] = GraphEdge(
                    id=edge_algo_id,
                    source=component_id,
                    target=algo_id,
                    relationship="USES_ALGORITHM",
                    properties={"usage": usage, "risk_level": risk_level},
                )

            # 4. Library Node
            if library:
                lib_id = f"lib:{library.lower()}"
                if lib_id not in nodes_dict:
                    nodes_dict[lib_id] = GraphNode(
                        id=lib_id,
                        label=library,
                        type="library",
                        properties={"library": library},
                    )
                edge_lib_id = f"edge:{component_id}->{lib_id}"
                if edge_lib_id not in edges_dict:
                    edges_dict[edge_lib_id] = GraphEdge(
                        id=edge_lib_id,
                        source=component_id,
                        target=lib_id,
                        relationship="LINKS_LIBRARY",
                    )

            # 5. Network Endpoint Node
            if hostname:
                ep_id = f"endpoint:{hostname}:{port or 443}"
                if ep_id not in nodes_dict:
                    nodes_dict[ep_id] = GraphNode(
                        id=ep_id,
                        label=f"{hostname}:{port or 443}",
                        type="endpoint",
                        properties={"hostname": hostname, "port": port},
                    )
                    edge_ep_id = f"edge:{app_id}->{ep_id}"
                    edges_dict[edge_ep_id] = GraphEdge(
                        id=edge_ep_id,
                        source=app_id,
                        target=ep_id,
                        relationship="EXPOSES_ENDPOINT",
                    )
                # Link endpoint -> algorithm
                edge_ep_algo_id = f"edge:{ep_id}->{algo_id}"
                edges_dict[edge_ep_algo_id] = GraphEdge(
                    id=edge_ep_algo_id,
                    source=ep_id,
                    target=algo_id,
                    relationship="SECURED_BY",
                )

            # 6. Data Asset Node (Sensitivity)
            if sensitivity in ("CRITICAL", "HIGH", "MEDIUM"):
                data_id = f"data:{sensitivity.lower()}"
                if data_id not in nodes_dict:
                    nodes_dict[data_id] = GraphNode(
                        id=data_id,
                        label=f"{sensitivity} Data",
                        type="data_asset",
                        properties={"sensitivity": sensitivity},
                    )
                edge_data_id = f"edge:{algo_id}->{data_id}"
                if edge_data_id not in edges_dict:
                    edges_dict[edge_data_id] = GraphEdge(
                        id=edge_data_id,
                        source=algo_id,
                        target=data_id,
                        relationship="PROTECTS_DATA",
                        properties={"sensitivity": sensitivity},
                    )

                # Check Critical Chain: Sensitive Data + Quantum-Vulnerable Algorithm
                if quantum_status == "vulnerable" and sensitivity in ("CRITICAL", "HIGH"):
                    critical_chains.append({
                        "data_asset": f"{sensitivity} Data",
                        "algorithm": algorithm,
                        "component": component_id,
                        "risk_score": risk_score,
                        "hndl_risk": "CRITICAL" if sensitivity == "CRITICAL" else "HIGH",
                        "remediation": f"Replace {algorithm} protecting {sensitivity} data with NIST PQC standard.",
                    })

        # Summary statistics
        node_counts: Dict[str, int] = {}
        for n in nodes_dict.values():
            node_counts[n.type] = node_counts.get(n.type, 0) + 1

        summary = {
            "total_nodes": len(nodes_dict),
            "total_edges": len(edges_dict),
            "node_types": node_counts,
            "critical_chains_count": len(critical_chains),
        }

        return GraphData(
            nodes=list(nodes_dict.values()),
            edges=list(edges_dict.values()),
            summary=summary,
            critical_chains=critical_chains,
        )

    @classmethod
    def generate_cypher_statements(cls, graph: GraphData) -> List[str]:
        """
        Generate Cypher statements to sync the GraphData into a Neo4j database.
        """
        statements: List[str] = []

        # Create nodes
        for node in graph.nodes:
            props = ", ".join(f"{k}: '{str(v).replace("'", "\\'")}'" for k, v in node.properties.items())
            props_str = f" {{{props}}}" if props else ""
            stmt = f"MERGE (n:{node.type.capitalize()} {{id: '{node.id}'}}) ON CREATE SET n.label = '{node.label}'{props_str};"
            statements.append(stmt)

        # Create edges
        for edge in graph.edges:
            rel = edge.relationship
            stmt = (
                f"MATCH (a {{id: '{edge.source}'}}), (b {{id: '{edge.target}'}}) "
                f"MERGE (a)-[r:{rel}]->(b);"
            )
            statements.append(stmt)

        return statements
