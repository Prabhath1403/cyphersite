"""Neo4j async driver client for persistent graph storage."""

import logging
from typing import Any, Dict, List, Optional

from app.config import settings

logger = logging.getLogger(__name__)

# Global driver instance (initialized lazily)
_driver = None


def _get_driver():
    """Get or create the Neo4j driver instance (lazy singleton)."""
    global _driver
    if _driver is None:
        try:
            from neo4j import GraphDatabase
            _driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                max_connection_pool_size=25,
            )
            logger.info('Neo4j driver initialized: %s', settings.NEO4J_URI)
        except Exception as e:
            logger.warning('Neo4j driver initialization failed (non-fatal): %s', e)
            return None
    return _driver


async def close_driver():
    """Close the Neo4j driver on shutdown."""
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
        logger.info('Neo4j driver closed')


def sync_graph_to_neo4j(graph_data) -> bool:
    """Synchronously write a GraphData object to Neo4j.
    
    Returns True if sync was successful, False if Neo4j is unavailable.
    This is designed to be non-fatal — if Neo4j is down, the app continues
    serving graphs from PostgreSQL data.
    """
    driver = _get_driver()
    if driver is None:
        logger.warning('Neo4j sync skipped — driver not available')
        return False
    
    try:
        with driver.session() as session:
            # Clear existing data for this scan (if scan_id present)
            scan_id = graph_data.summary.get('scan_id', '')
            if scan_id:
                session.run(
                    'MATCH (n {scan_id: $scan_id}) DETACH DELETE n',
                    scan_id=scan_id,
                )
            
            # Create nodes
            for node in graph_data.nodes:
                props = {**node.properties, 'label': node.label, 'name': node.name, 'node_type': node.type}
                if scan_id:
                    props['scan_id'] = scan_id
                session.run(
                    f'MERGE (n:{node.type.capitalize()} {{id: $id}}) '
                    'SET n += $props',
                    id=node.id,
                    props=props,
                )
            
            # Create edges
            for edge in graph_data.edges:
                session.run(
                    f'MATCH (a {{id: $source}}), (b {{id: $target}}) '
                    f'MERGE (a)-[r:{edge.relationship}]->(b) '
                    'SET r += $props',
                    source=edge.source,
                    target=edge.target,
                    props=edge.properties,
                )
        
        logger.info('Neo4j sync completed: %d nodes, %d edges', 
                    len(graph_data.nodes), len(graph_data.edges))
        return True
    except Exception as e:
        logger.warning('Neo4j sync failed (non-fatal): %s', e)
        return False


def query_graph_from_neo4j(scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Query a graph from Neo4j by scan_id. Returns dict or None if unavailable."""
    driver = _get_driver()
    if driver is None:
        return None
    
    try:
        with driver.session() as session:
            if scan_id:
                nodes_result = session.run(
                    'MATCH (n {scan_id: $scan_id}) RETURN n',
                    scan_id=scan_id,
                )
            else:
                nodes_result = session.run('MATCH (n) RETURN n LIMIT 500')
            
            nodes = []
            for record in nodes_result:
                node = record['n']
                nodes.append({
                    'id': node.get('id', ''),
                    'label': node.get('label', ''),
                    'name': node.get('name', ''),
                    'type': node.get('node_type', ''),
                    'properties': dict(node),
                })
            
            if scan_id:
                edges_result = session.run(
                    'MATCH (a {scan_id: $scan_id})-[r]->(b) '
                    'RETURN a.id AS source, b.id AS target, type(r) AS rel, properties(r) AS props',
                    scan_id=scan_id,
                )
            else:
                edges_result = session.run(
                    'MATCH (a)-[r]->(b) '
                    'RETURN a.id AS source, b.id AS target, type(r) AS rel, properties(r) AS props '
                    'LIMIT 1000',
                )
            
            edges = []
            for record in edges_result:
                edges.append({
                    'id': f"{record['source']}->{record['target']}",
                    'source': record['source'],
                    'target': record['target'],
                    'type': record['rel'],
                    'relationship': record['rel'],
                    'properties': dict(record['props']) if record['props'] else {},
                })
            
            return {'nodes': nodes, 'edges': edges} if nodes else None
    except Exception as e:
        logger.warning('Neo4j query failed (non-fatal): %s', e)
        return None


def check_neo4j_health() -> Dict[str, Any]:
    """Check Neo4j connectivity. Returns status dict."""
    driver = _get_driver()
    if driver is None:
        return {'status': 'unavailable', 'message': 'Driver not initialized'}
    try:
        driver.verify_connectivity()
        return {'status': 'connected', 'uri': settings.NEO4J_URI}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
