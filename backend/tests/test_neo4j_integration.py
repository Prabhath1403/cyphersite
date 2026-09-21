import uuid
import pytest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.core.graph.neo4j_client import sync_graph_to_neo4j, check_neo4j_health, query_graph_from_neo4j
from app.core.graph.engine import GraphEngine
from app.core.graph.models import GraphData


client = TestClient(app)


def test_neo4j_client_graceful_when_unavailable():
    # Mock _get_driver to return None, simulating Neo4j being unavailable
    with patch('app.core.graph.neo4j_client._get_driver', return_value=None):
        graph = GraphData(nodes=[], edges=[], summary={}, critical_chains=[])
        result = sync_graph_to_neo4j(graph)
        assert result is False


def test_neo4j_health_check_unavailable():
    with patch('app.core.graph.neo4j_client._get_driver', return_value=None):
        health = check_neo4j_health()
        assert health['status'] == 'unavailable'


def test_graph_engine_sync_to_neo4j_method():
    assert hasattr(GraphEngine, 'sync_to_neo4j')
    assert callable(getattr(GraphEngine, 'sync_to_neo4j'))
    
    with patch('app.core.graph.neo4j_client.sync_graph_to_neo4j', return_value=True) as mock_sync:
        graph = GraphData(nodes=[], edges=[], summary={}, critical_chains=[])
        result = GraphEngine.sync_to_neo4j(graph)
        assert result is True
        mock_sync.assert_called_once_with(graph)


@pytest.mark.asyncio
async def test_graph_api_still_works_without_neo4j(client, db_session: AsyncSession):
    # Create a mock scan
    import uuid
    from app.models.scan import ScanJob
    
    scan_id = uuid.uuid4()
    mock_scan = ScanJob(
        id=scan_id,
        target="Mock Target",
        status="completed"
    )
    db_session.add(mock_scan)
    await db_session.commit()
    
    with patch('app.core.graph.neo4j_client._get_driver', return_value=None):
        response = await client.get(f'/api/graph/{scan_id}')
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "edges" in data

@pytest.mark.asyncio
async def test_neo4j_graph_endpoint_returns_503(client):
    with patch('app.core.graph.neo4j_client._get_driver', return_value=None):
        scan_id = uuid.uuid4()
        response = await client.get(f'/api/graph/neo4j/{scan_id}')
        assert response.status_code == 503
