"""
Git Monitor Engine — Core real-time synchronization engine.

Processes incremental file commits, scans modified code via AST in milliseconds,
updates canonical CryptoAsset records, recalculates PQC risk posture, re-builds CBOM,
synchronizes Topology Graphs, and streams live telemetry via WebSockets.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

import httpx
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset
from app.models.cbom import CBOMRecord
from app.models.git_monitor import GitMonitorEvent
from app.core.cbom.builder import build_cbom, cbom_to_json_string
from app.core.graph import GraphEngine
from app.core.git_monitor.incremental_scanner import IncrementalScanner
from app.core.source_scanner import CryptoFindingData

logger = logging.getLogger(__name__)


class GitMonitorEngine:
    """Orchestrates second-by-second Git monitoring and instant single-file remediation."""

    @classmethod
    async def fetch_remote_file_content(
        cls,
        repository: str,
        file_path: str,
        branch: str = "main",
        token: Optional[str] = None,
    ) -> Optional[str]:
        """Fetch raw file content from GitHub REST API."""
        auth_token = token or settings.GITHUB_TOKEN
        headers = {
            "Accept": "application/vnd.github.v3.raw",
            "User-Agent": "CipherSight-Git-Monitor",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        clean_repo = repository.replace("https://github.com/", "").replace(".git", "").strip("/")
        url = f"https://raw.githubusercontent.com/{clean_repo}/{branch}/{file_path}"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    return resp.text
                logger.warning("Could not fetch remote file %s: HTTP %s", url, resp.status_code)
        except Exception as err:
            logger.warning("Failed to fetch remote file content: %s", err)
        return None

    @classmethod
    async def process_file_change(
        cls,
        db: AsyncSession,
        repository: str,
        file_path: str,
        content: Optional[str] = None,
        commit_id: Optional[str] = None,
        commit_message: Optional[str] = None,
        author: Optional[str] = None,
        branch: str = "main",
        action: str = "modified",
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Incrementally scan a single file changed in a Git push or edit,
        update database assets, re-calculate posture, update graph, and broadcast.
        """
        start_time = time.perf_counter()
        clean_repo = repository.strip()
        commit_hash = commit_id or f"commit-{int(time.time())}"
        commit_msg = commit_message or f"Update {file_path}"
        author_name = author or "Developer"

        logger.info(
            "⚡ Git Monitor: Processing %s in %s (commit %s)",
            file_path, clean_repo, commit_hash[:8]
        )

        # 1. Locate or create corresponding ScanJob
        repo_short = clean_repo.split("/")[-1]
        scan_query = select(ScanJob).where(
            (ScanJob.target == clean_repo) |
            (ScanJob.target.like(f"%{clean_repo}%")) |
            (ScanJob.target.like(f"%{repo_short}%"))
        ).order_by(desc(ScanJob.created_at))

        scan_res = await db.execute(scan_query)
        scan = scan_res.scalars().first()

        if not scan:
            scan = ScanJob(
                target=clean_repo,
                scan_type="source",
                status="completed",
                scan_depth="quick",
            )
            db.add(scan)
            await db.flush()

        # 2. Query existing CryptoAsset findings for this file and scan
        old_assets_query = select(CryptoAsset).where(
            CryptoAsset.scan_id == scan.id,
            (CryptoAsset.file_path == file_path) |
            (CryptoAsset.file_path.endswith(file_path)) |
            (CryptoAsset.source_location == file_path)
        )
        old_assets_res = await db.execute(old_assets_query)
        old_assets = old_assets_res.scalars().all()

        old_vuln_count = sum(1 for a in old_assets if a.pqc_status in ("VULNERABLE", "HYBRID_READY"))
        old_algos = [a.algorithm for a in old_assets if a.algorithm]

        # 3. Retrieve code content if not provided
        code_to_scan = content
        if code_to_scan is None and action != "removed":
            # Try reading local disk first
            local_p = Path(file_path)
            if local_p.exists() and local_p.is_file():
                code_to_scan = local_p.read_text(encoding="utf-8", errors="replace")
            else:
                # Try fetching from remote GitHub
                code_to_scan = await cls.fetch_remote_file_content(
                    repository=clean_repo,
                    file_path=file_path,
                    branch=branch,
                    token=token,
                )

        # 4. Scan the single changed file
        new_findings: List[CryptoFindingData] = []
        if action != "removed" and code_to_scan:
            new_findings = IncrementalScanner.scan_source_code(
                code=code_to_scan,
                file_path=file_path,
                repository=clean_repo,
            )

        new_vuln_count = sum(1 for f in new_findings if (f.pqc_status or "").upper() == "VULNERABLE")
        new_safe_count = sum(1 for f in new_findings if (f.pqc_status or "").upper() == "QUANTUM_SAFE")
        new_algos = [f.algorithm for f in new_findings if f.algorithm]

        # 5. Determine remediation delta
        vulns_fixed = max(0, old_vuln_count - new_vuln_count)
        if vulns_fixed > 0:
            action_status = "remediated"
            diff_summary = (
                f"Remediated {vulns_fixed} vulnerability in {file_path}. "
                f"Replaced {', '.join(old_algos) if old_algos else 'legacy cipher'} with "
                f"{', '.join(new_algos) if new_algos else 'Quantum-Safe implementation'}."
            )
        elif new_vuln_count > old_vuln_count:
            action_status = "new_vulnerabilities"
            diff_summary = f"New vulnerable crypto detected in {file_path}: {', '.join(new_algos)}."
        elif action == "removed":
            action_status = "removed"
            diff_summary = f"Removed file {file_path}, eliminating {len(old_assets)} tracked cryptographic usages."
        else:
            action_status = "updated"
            diff_summary = f"Updated {file_path} with {len(new_findings)} active cryptographic usages."

        # 6. Delete old findings for this file
        for old in old_assets:
            await db.delete(old)
        await db.flush()

        # 7. Insert new findings
        persisted_assets: List[CryptoAsset] = []
        for nf in new_findings:
            kw = nf.to_orm_kwargs()
            kw["file_path"] = file_path
            kw["source_location"] = file_path
            kw["repository"] = clean_repo
            asset = CryptoAsset(scan_id=scan.id, **kw)
            db.add(asset)
            persisted_assets.append(asset)
        await db.flush()

        # 8. Recalculate ScanJob totals
        totals_query = select(
            func.count(CryptoAsset.id),
            func.count().filter(CryptoAsset.pqc_status == "QUANTUM_SAFE"),
            func.count().filter(CryptoAsset.pqc_status == "HYBRID_READY"),
            func.count().filter(CryptoAsset.pqc_status == "VULNERABLE"),
        ).where(CryptoAsset.scan_id == scan.id)

        totals_res = await db.execute(totals_query)
        total, qs, hyb, vuln = totals_res.first()
        scan.total_assets = total or 0
        scan.quantum_safe_count = qs or 0
        scan.hybrid_count = hyb or 0
        scan.vulnerable_count = vuln or 0
        scan.completed_at = datetime.utcnow()
        await db.flush()

        # 9. Rebuild CBOM
        all_assets_query = select(CryptoAsset).where(CryptoAsset.scan_id == scan.id)
        all_assets_res = await db.execute(all_assets_query)
        all_assets = all_assets_res.scalars().all()

        try:
            cbom_dict = build_cbom(
                scan_id=str(scan.id),
                target=clean_repo,
                assets=all_assets,
            )
            cbom_json = cbom_to_json_string(cbom_dict)
            cbom_query = select(CBOMRecord).where(CBOMRecord.scan_id == scan.id)
            cbom_res = await db.execute(cbom_query)
            existing_cbom = cbom_res.scalars().first()
            if existing_cbom:
                existing_cbom.cyclonedx_json = cbom_json
            else:
                db.add(CBOMRecord(scan_id=scan.id, cyclonedx_json=cbom_json))
        except Exception as err:
            logger.warning("Failed to update CBOM record: %s", err)

        # 10. Sync Graph and Neo4j
        try:
            graph_data = GraphEngine.build_graph(
                findings=all_assets,
                target_name=scan.target,
                scan_id=str(scan.id),
            )
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, GraphEngine.sync_to_neo4j, graph_data)
        except Exception as err:
            logger.debug("Graph engine sync non-fatal warning: %s", err)

        # 11. Record GitMonitorEvent audit log
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        event = GitMonitorEvent(
            repository=clean_repo,
            branch=branch,
            commit_id=commit_hash,
            commit_message=commit_msg,
            author=author_name,
            file_path=file_path,
            action=action_status,
            vulnerabilities_fixed=vulns_fixed,
            vulnerabilities_remaining=scan.vulnerable_count,
            quantum_safe_count=scan.quantum_safe_count,
            scan_id=scan.id,
            duration_ms=round(duration_ms, 2),
            diff_summary=diff_summary,
        )
        db.add(event)
        await db.commit()
        await db.refresh(event)

        # 12. Broadcast Real-Time Telemetry to all WebSocket clients
        telemetry_payload = {
            "event": "GIT_COMMIT_PROCESSED",
            "event_id": str(event.id),
            "repository": clean_repo,
            "branch": branch,
            "commit_id": commit_hash,
            "commit_message": commit_msg,
            "author": author_name,
            "file_path": file_path,
            "action": action_status,
            "vulnerabilities_fixed": vulns_fixed,
            "vulnerabilities_remaining": scan.vulnerable_count,
            "diff_summary": diff_summary,
            "duration_ms": round(duration_ms, 2),
            "scan_id": str(scan.id),
            "timestamp": datetime.utcnow().isoformat(),
            "stats": {
                "total_assets": scan.total_assets,
                "quantum_safe_count": scan.quantum_safe_count,
                "hybrid_count": scan.hybrid_count,
                "vulnerable_count": scan.vulnerable_count,
            },
        }

        try:
            from app.routers.ws import manager
            await manager.broadcast_git_event(telemetry_payload)
        except Exception as err:
            logger.warning("Could not broadcast git event via WebSocket: %s", err)

        logger.info(
            "✅ Git Monitor complete in %.2fms: %s (%d fixed, %d vuln remaining)",
            duration_ms, diff_summary, vulns_fixed, scan.vulnerable_count
        )

        return telemetry_payload

    @classmethod
    async def process_commit_payload(
        cls,
        db: AsyncSession,
        payload: Dict[str, Any],
        token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Process an entire GitHub push webhook payload containing one or more commits.
        """
        repo_data = payload.get("repository", {})
        repo_name = repo_data.get("full_name") or repo_data.get("name") or "unknown/repo"
        ref = payload.get("ref", "refs/heads/main")
        branch = ref.split("/")[-1] if "/" in ref else "main"

        commits = payload.get("commits", [])
        if not commits and "head_commit" in payload and payload["head_commit"]:
            commits = [payload["head_commit"]]

        results: List[Dict[str, Any]] = []

        for commit in commits:
            cid = commit.get("id", "head")
            msg = commit.get("message", "Commit update")
            author = commit.get("author", {}).get("name") or commit.get("committer", {}).get("name") or "Developer"

            added_files = commit.get("added", [])
            modified_files = commit.get("modified", [])
            removed_files = commit.get("removed", [])

            # Process added & modified files
            for f in added_files + modified_files:
                if not f.endswith(".py"):
                    continue
                res = await cls.process_file_change(
                    db=db,
                    repository=repo_name,
                    file_path=f,
                    commit_id=cid,
                    commit_message=msg,
                    author=author,
                    branch=branch,
                    action="added" if f in added_files else "modified",
                    token=token,
                )
                results.append(res)

            # Process removed files
            for f in removed_files:
                if not f.endswith(".py"):
                    continue
                res = await cls.process_file_change(
                    db=db,
                    repository=repo_name,
                    file_path=f,
                    commit_id=cid,
                    commit_message=msg,
                    author=author,
                    branch=branch,
                    action="removed",
                    token=token,
                )
                results.append(res)

        return results
