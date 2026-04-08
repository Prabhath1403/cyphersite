"""
WebSocket router — real-time scan progress streaming.

Connects to Redis pub/sub to forward scan progress events
to connected WebSocket clients.
"""

import asyncio
import json
import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for scan progress streaming."""

    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        """Accept and register a WebSocket connection."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        logger.info(f"WebSocket connected for scan {scan_id}")

    def disconnect(self, websocket: WebSocket, scan_id: str):
        """Remove a WebSocket connection."""
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        logger.info(f"WebSocket disconnected for scan {scan_id}")

    async def broadcast(self, scan_id: str, message: dict):
        """Broadcast a message to all connections for a scan."""
        if scan_id in self.active_connections:
            disconnected = []
            for ws in self.active_connections[scan_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    disconnected.append(ws)

            for ws in disconnected:
                self.disconnect(ws, scan_id)


manager = ConnectionManager()


@router.websocket("/ws/scan/{scan_id}")
async def scan_progress_websocket(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan progress.

    Subscribes to Redis pub/sub channel for the scan and
    forwards all progress events to the connected client.

    Events format:
    {
        "event": "discovery"|"tls_scan"|"pqc_check"|"cbom_build"|"complete",
        "progress": 0-100,
        "message": "Human-readable progress message"
    }
    """
    await manager.connect(websocket, scan_id)

    try:
        # Subscribe to Redis pub/sub for this scan
        redis_client = aioredis.from_url(settings.REDIS_URL)
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(f"scan:{scan_id}")

        # Send initial connection message
        await websocket.send_json({
            "event": "connected",
            "progress": 0,
            "message": "Connected to scan progress stream",
            "scan_id": scan_id,
        })

        # Listen for Redis messages and forward to WebSocket
        async def listen_redis():
            try:
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        data = json.loads(message["data"])
                        await websocket.send_json(data)

                        # Stop listening if scan is complete
                        if data.get("event") in ("complete", "error"):
                            break
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Redis listener error: {e}")

        # Run Redis listener and client receiver concurrently
        redis_task = asyncio.create_task(listen_redis())

        try:
            while True:
                # Keep connection alive by reading client messages
                data = await websocket.receive_text()
                # Client can send ping messages
                if data == "ping":
                    await websocket.send_json({"event": "pong"})
        except WebSocketDisconnect:
            redis_task.cancel()

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
    finally:
        manager.disconnect(websocket, scan_id)
        try:
            await pubsub.unsubscribe(f"scan:{scan_id}")
            await redis_client.close()
        except Exception:
            pass
