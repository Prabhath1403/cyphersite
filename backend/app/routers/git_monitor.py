"""
Git Monitor Router — Real-time continuous GitHub & Git file change monitoring.

Handles incoming GitHub webhooks, live filesystem watcher controls,
interactive push simulations, and instant vulnerability remediation streaming.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.git_monitor import GitMonitorEvent
from app.models.scan import ScanJob
from app.core.git_monitor import GitMonitorEngine, watcher_instance

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/git-monitor", tags=["git-monitor"])


# ── Schemas ─────────────────────────────────────────────────────────────

class SimulatePushRequest(BaseModel):
    repository: str = Field(default="Prabhath1403/cyphersite", description="Repository identifier or full name")
    branch: str = Field(default="main", description="Git branch")
    file_path: str = Field(default="services/auth_tokens.py", description="Relative file path in repository")
    code_content: str = Field(description="Full source code content of the modified file")
    commit_message: str = Field(
        default="fix: eliminate Shor-vulnerable cipher; adopt NIST FIPS 203 ML-KEM",
        description="Commit message"
    )
    author: str = Field(default="Developer <dev@ciphersight.io>", description="Commit author")
    commit_id: Optional[str] = Field(default=None, description="Optional commit SHA")


class TriggerPresetRequest(BaseModel):
    preset_id: str = Field(description="Preset identifier (e.g. fix_rsa_to_mlkem)")
    repository: str = Field(default="Prabhath1403/cyphersite", description="Repository to apply preset to")


class WatcherControlRequest(BaseModel):
    repository: str = Field(default="Prabhath1403/cyphersite", description="GitHub repository (owner/repo) or identifier")
    branch: str = Field(default="main", description="Git branch")
    mode: str = Field(default="remote", description="'remote' (GitHub API commits) or 'local' (filesystem)")
    path: Optional[str] = Field(default=None, description="Local path if mode is 'local'")
    interval: float = Field(default=3.0, ge=1.0, le=60.0, description="Check frequency in seconds")
    token: Optional[str] = Field(default=None, description="Optional GitHub Personal Access Token")


# ── Preset Code Blueprints ──────────────────────────────────────────────

PRESETS = {
    "fix_rsa_to_mlkem": {
        "title": "Remediate RSA-2048 to NIST FIPS 203 ML-KEM",
        "file_path": "services/crypto_service.py",
        "description": "Replaces Shor-vulnerable RSA-2048 key exchange with post-quantum lattice-based ML-KEM (Module-Lattice Key Encapsulation Mechanism) and AES-256-GCM symmetric transport.",
        "code_before": """# Legacy Vulnerable Crypto Implementation
from cryptography.hazmat.primitives.asymmetric import rsa

# VULNERABLE TO QUANTUM COMPUTERS (Shor's Algorithm)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
""",
        "code_after": """# Quantum-Proof Remediated Implementation
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# REMEDIATED: Replaced RSA with NIST FIPS 203 (ML-KEM-768) + AES-256-GCM
shared_key = AESGCM.generate_key(bit_length=256)
cipher = AESGCM(shared_key)
""",
        "commit_message": "fix(crypto): migrate from RSA-2048 to NIST FIPS 203 ML-KEM and AES-256-GCM",
        "vulnerabilities_fixed": 1,
    },
    "fix_md5_to_sha256": {
        "title": "Remediate Broken MD5/SHA-1 to Secure SHA-256",
        "file_path": "services/token_verifier.py",
        "description": "Replaces cryptographically broken MD5 hash algorithm with collision-resistant SHA-256.",
        "code_before": """# Weak Hash Usage
import hashlib

def generate_checksum(data: bytes) -> str:
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(data).hexdigest()
""",
        "code_after": """# Quantum-Resistant Hash Usage
import hashlib

def generate_checksum(data: bytes) -> str:
    # REMEDIATED: SHA-256 with Grover quantum security margin >= 128 bits
    return hashlib.sha256(data).hexdigest()
""",
        "commit_message": "fix(security): deprecate broken MD5 in favor of SHA-256 checksums",
        "vulnerabilities_fixed": 1,
    },
    "fix_des_to_aesgcm": {
        "title": "Remediate Legacy 3DES-CBC to AES-256-GCM",
        "file_path": "storage/encryption.py",
        "description": "Upgrades weak 3DES encryption to authenticated AES-256-GCM (Galois/Counter Mode).",
        "code_before": """from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# VULNERABLE: 3DES has 112-bit effective key and Sweet32 block collision vulnerability
cipher = Cipher(algorithms.TripleDES(b"123456781234567812345678"), modes.CBC(b"12345678"))
""",
        "code_after": """from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# REMEDIATED: Authenticated symmetric encryption AES-256-GCM (Quantum Safe)
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
""",
        "commit_message": "fix(storage): migrate database column encryption from 3DES to AES-256-GCM",
        "vulnerabilities_fixed": 1,
    },
    "introduce_vulnerable_rsa": {
        "title": "Simulate Inadvertent Vulnerability Introduction",
        "file_path": "services/crypto_service.py",
        "description": "Simulates a developer mistakenly adding a legacy RSA-1024 or RC4 call to test detection alerts.",
        "code_before": "",
        "code_after": """from cryptography.hazmat.primitives.asymmetric import rsa

# INADVERTENT REGRESSION: Legacy RSA-1024 introduced
key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
""",
        "commit_message": "feat(temp): add legacy RSA test endpoint",
        "vulnerabilities_fixed": 0,
    },
}


# ── Webhook Endpoint ───────────────────────────────────────────────────

@router.post("/webhook")
async def github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    GitHub Webhook receiver for real-time repository monitoring.

    Triggered on every push event to a GitHub repository:
    - Extracts modified, added, and deleted files
    - Executes instantaneous single-file incremental AST scans
    - Synchronizes CryptoAsset records, CBOM, and Topology Graph
    - Emits live WebSocket telemetry to all connected CipherSight clients
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = request.headers.get("X-GitHub-Event", "push")
    if event_type == "ping":
        return {"status": "pong", "message": "GitHub Webhook registered successfully"}

    if event_type != "push":
        return {"status": "ignored", "message": f"Event type '{event_type}' not processed; push events monitored"}

    results = await GitMonitorEngine.process_commit_payload(db=db, payload=payload)
    return {
        "status": "success",
        "event": "push",
        "files_processed": len(results),
        "updates": results,
    }


# ── Push Simulation & Preset Endpoints ─────────────────────────────────

@router.post("/simulate-push")
async def simulate_git_push(
    body: SimulatePushRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Simulate a developer pushing a code edit or vulnerability remediation to Git.

    Executes instantaneous single-file incremental scanning, updates the
    CryptoAsset inventory and Topology Graph, and pushes real-time WebSocket telemetry.
    """
    result = await GitMonitorEngine.process_file_change(
        db=db,
        repository=body.repository,
        file_path=body.file_path,
        content=body.code_content,
        commit_id=body.commit_id,
        commit_message=body.commit_message,
        author=body.author,
        branch=body.branch,
        action="modified",
    )
    return result


@router.get("/presets")
async def get_remediation_presets():
    """Retrieve pre-configured vulnerability fix scenarios for interactive demonstration."""
    return [
        {"id": k, **v} for k, v in PRESETS.items()
    ]


@router.post("/trigger-preset")
async def trigger_preset(
    body: TriggerPresetRequest,
    db: AsyncSession = Depends(get_db),
):
    """Trigger a pre-configured vulnerability remediation scenario."""
    preset = PRESETS.get(body.preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail=f"Preset '{body.preset_id}' not found")

    result = await GitMonitorEngine.process_file_change(
        db=db,
        repository=body.repository,
        file_path=preset["file_path"],
        content=preset["code_after"],
        commit_message=preset["commit_message"],
        author="Security Engineer <security@ciphersight.io>",
        action="modified",
    )
    return {
        "preset": preset["title"],
        "result": result,
    }


# ── Audit History & Status ──────────────────────────────────────────────

@router.get("/events")
async def get_git_events(
    limit: int = Query(default=50, ge=1, le=200),
    repository: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve the real-time audit stream of processed Git commits and file remediations."""
    query = select(GitMonitorEvent).order_by(desc(GitMonitorEvent.created_at)).limit(limit)
    if repository:
        query = query.where(GitMonitorEvent.repository.like(f"%{repository}%"))

    res = await db.execute(query)
    events = res.scalars().all()
    return [e.to_dict() for e in events]


@router.get("/status")
async def get_git_monitor_status(db: AsyncSession = Depends(get_db)):
    """Retrieve live monitoring status and telemetry counts."""
    watcher_status = watcher_instance.get_status()

    # Query total events count
    events_count_res = await db.execute(select(GitMonitorEvent.id))
    total_events = len(events_count_res.scalars().all())

    # Query last processed event
    last_event_res = await db.execute(
        select(GitMonitorEvent).order_by(desc(GitMonitorEvent.created_at)).limit(1)
    )
    last_event = last_event_res.scalars().first()

    return {
        "monitor_active": True,
        "second_to_second_mode": True,
        "watcher": watcher_status,
        "total_events_processed": total_events,
        "last_event": last_event.to_dict() if last_event else None,
    }


@router.post("/watch/start")
async def start_watcher(body: WatcherControlRequest):
    """Start continuous second-to-second push monitoring for a repository."""
    try:
        await watcher_instance.start(
            repository=body.repository,
            branch=body.branch,
            mode=body.mode,
            target_dir=body.path,
            interval=body.interval,
            token=body.token,
        )
        return {
            "status": "started",
            "watcher": watcher_instance.get_status(),
        }
    except Exception as err:
        raise HTTPException(status_code=400, detail=str(err))


@router.post("/watch/stop")
async def stop_watcher():
    """Stop continuous second-to-second push monitoring."""
    await watcher_instance.stop()
    return {
        "status": "stopped",
        "watcher": watcher_instance.get_status(),
    }


@router.post("/check-now")
async def check_pushes_now():
    """Immediately poll GitHub for newly pushed commits on the monitored repository."""
    results = await watcher_instance.check_now()
    return {
        "status": "checked",
        "pushes_detected": len(results),
        "updates": results,
    }


@router.get("/webhook-info")
async def get_webhook_info():
    """Information and instructions for setting up GitHub Webhook integration."""
    return {
        "webhook_url": "/api/git-monitor/webhook",
        "content_type": "application/json",
        "events": ["push"],
        "description": "Send push events to CipherSight for real-time incremental single-file PQC analysis and topology updating.",
        "instructions": [
            "1. Navigate to your GitHub repository -> Settings -> Webhooks",
            "2. Click 'Add webhook'",
            "3. Enter Payload URL: https://<your-ciphersight-domain>/api/git-monitor/webhook",
            "4. Select Content type: application/json",
            "5. Select 'Just the push event'",
            "6. Click 'Add webhook'. CipherSight will now analyze changed files second-to-second upon every git push!",
        ],
    }
