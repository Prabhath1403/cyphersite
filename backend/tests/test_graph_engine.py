"""
Tests for the Cryptographic Topology Graph Engine and Graph API endpoints.
"""

import pytest
from app.core.source_scanner import CryptoFindingData
from app.core.graph import GraphEngine, GraphNode, GraphEdge, GraphData


def test_build_graph_structure():
    """Test building a graph from diverse cryptographic findings."""
    findings = [
        CryptoFindingData(
            name="RSA JWT Signer",
            asset_type="source_code_usage",
            source_type="source_code",
            algorithm="RSA-2048",
            library="cryptography",
            file_path="/app/auth/jwt.py",
            sensitivity="CRITICAL",
            quantum_status="vulnerable",
            pqc_status="VULNERABLE",
            risk_score=85.0,
            usage="digital_signature",
        ),
        CryptoFindingData(
            name="Public TLS Endpoint",
            asset_type="network_endpoint",
            source_type="network",
            algorithm="ECDSA-P256",
            hostname="api.cyphercite.io",
            port=443,
            quantum_status="vulnerable",
            pqc_status="VULNERABLE",
            risk_score=80.0,
        ),
        CryptoFindingData(
            name="ML-KEM Key Exchange",
            asset_type="binary_usage",
            source_type="binary",
            algorithm="ML-KEM-768",
            library="liboqs",
            file_path="/usr/lib/libcrypto.so",
            sensitivity="HIGH",
            quantum_status="safe",
            pqc_status="QUANTUM_SAFE",
            risk_score=0.0,
        ),
    ]

    graph = GraphEngine.build_graph(findings, target_name="CyberApp", scan_id="scan-123")
    data = graph.to_dict()

    assert data["summary"]["total_nodes"] >= 6
    assert data["summary"]["total_edges"] >= 5

    types = {n["type"] for n in data["nodes"]}
    assert "application" in types
    assert "component" in types
    assert "algorithm" in types
    assert "library" in types
    assert "endpoint" in types
    assert "data_asset" in types

    # Check critical chains (RSA-2048 protecting CRITICAL data)
    assert len(data["critical_chains"]) >= 1
    chain = data["critical_chains"][0]
    assert chain["algorithm"] == "RSA-2048"
    assert "CRITICAL" in chain["data_asset"]


def test_generate_cypher_statements():
    """Test Neo4j Cypher query generation."""
    nodes = [
        GraphNode(id="app:test", label="TestApp", type="application"),
        GraphNode(id="algo:rsa", label="RSA", type="algorithm", properties={"risk": 85}),
    ]
    edges = [
        GraphEdge(id="e1", source="app:test", target="algo:rsa", relationship="USES_ALGORITHM"),
    ]
    graph = GraphData(nodes=nodes, edges=edges)

    statements = GraphEngine.generate_cypher_statements(graph)
    assert len(statements) == 3
    assert any("MERGE (n:Application" in s for s in statements)
    assert any("MERGE (a)-[r:USES_ALGORITHM]->(b)" in s for s in statements)


@pytest.mark.asyncio
async def test_graph_api_endpoints(client, tmp_path):
    """Test GET /api/graph/{scan_id} and GET /api/graph."""
    # 1. Create a dummy scan with findings first via source scan
    py_file = tmp_path / "auth.py"
    py_file.write_text("import hashlib\nh = hashlib.sha256(b'test').hexdigest()\n")

    resp = await client.post(
        "/api/scan/source",
        json={"path": str(tmp_path), "scan_depth": "standard"},
    )
    assert resp.status_code == 200
    scan_id = resp.json()["id"]

    # 2. Query graph for this scan
    graph_resp = await client.get(f"/api/graph/{scan_id}")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert "summary" in graph_data
    assert graph_data["summary"]["total_nodes"] >= 2

    # 3. Query enterprise aggregated graph
    ent_resp = await client.get("/api/graph")
    assert ent_resp.status_code == 200
    ent_data = ent_resp.json()
    assert "nodes" in ent_data
    assert len(ent_data["nodes"]) >= 2
