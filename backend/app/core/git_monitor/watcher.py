"""
Live Git Watcher — Continuous GitHub and repository push monitor.

Second-to-second observer that tracks remote GitHub repositories and local repositories:
- Detects new developer commits pushed to GitHub
- Identifies the specific files changed in the push
- Automatically fetches and incrementally scans the changed files
- Updates Crypto Inventory, Topology Graph, CBOM, and Dashboard in real time
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings
from app.database import async_session
from app.core.git_monitor.engine import GitMonitorEngine

logger = logging.getLogger(__name__)


class LiveGitWatcher:
    """Continuously monitors repositories for developer pushes and file updates."""

    def __init__(self):
        self._is_running = False
        self._watch_task: Optional[asyncio.Task] = None
        self._watch_dir: Optional[Path] = None
        self._repository_name: str = "Prabhath1403/cyphersite"
        self._branch: str = "main"
        self._mode: str = "remote"  # "remote" (GitHub API) or "local" (filesystem)
        self._github_token: Optional[str] = None
        self._last_commit_sha: Optional[str] = None
        self._file_mtimes: Dict[str, float] = {}
        self._poll_interval: float = 3.0  # seconds
        self._last_check_time: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return self._is_running

    def get_status(self) -> dict:
        return {
            "active": self._is_running,
            "mode": self._mode,
            "repository": self._repository_name,
            "branch": self._branch,
            "last_commit_sha": self._last_commit_sha,
            "poll_interval_seconds": self._poll_interval,
            "watched_directory": str(self._watch_dir) if self._watch_dir else None,
            "tracked_files_count": len(self._file_mtimes) if self._mode == "local" else None,
            "last_check_time": self._last_check_time,
        }

    async def start(
        self,
        repository: str = "Prabhath1403/cyphersite",
        branch: str = "main",
        mode: str = "remote",
        target_dir: Optional[str] = None,
        interval: float = 3.0,
        token: Optional[str] = None,
    ):
        """Start second-to-second continuous monitoring for pushes."""
        if self._is_running:
            await self.stop()

        self._repository_name = repository.strip()
        self._branch = branch.strip() or "main"
        self._mode = mode
        self._poll_interval = max(1.0, interval)
        self._github_token = token
        self._is_running = True

        if self._mode == "local" and target_dir:
            path = Path(target_dir).resolve()
            if not path.exists():
                raise ValueError(f"Target directory {target_dir} does not exist.")
            self._watch_dir = path
            self._file_mtimes = self._index_files(self._watch_dir)
        else:
            self._watch_dir = None
            self._file_mtimes = {}

        self._watch_task = asyncio.create_task(self._poll_loop())
        logger.info(
            "👀 Live Git Watcher started on [%s] (mode: %s, branch: %s, interval: %.1fs)",
            self._repository_name, self._mode, self._branch, self._poll_interval
        )

    async def stop(self):
        """Stop background watcher."""
        self._is_running = False
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
            self._watch_task = None
        logger.info("🛑 Live Git Watcher stopped.")

    async def check_now(self) -> List[Dict[str, Any]]:
        """Manually trigger an immediate check for new pushes on the monitored repository."""
        if self._mode == "remote":
            return await self._check_remote_github()
        elif self._mode == "local" and self._watch_dir:
            return await self._check_local_filesystem()
        return []

    def _index_files(self, root: Path) -> Dict[str, float]:
        mtimes = {}
        skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for f in filenames:
                if f.endswith(".py"):
                    full = os.path.join(dirpath, f)
                    try:
                        mtimes[full] = os.path.getmtime(full)
                    except OSError:
                        pass
        return mtimes

    async def _check_remote_github(self) -> List[Dict[str, Any]]:
        """Query GitHub API to detect new commits pushed to the repository."""
        from datetime import datetime
        self._last_check_time = datetime.utcnow().isoformat()

        clean_repo = self._repository_name.replace("https://github.com/", "").replace(".git", "").strip("/")
        if "/" not in clean_repo:
            return []

        owner, repo = clean_repo.split("/", 1)
        auth_token = self._github_token or settings.GITHUB_TOKEN
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CipherSight-Git-Monitor",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        results: List[Dict[str, Any]] = []

        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/commits?sha={self._branch}&per_page=1"
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
                    logger.debug("GitHub commits API returned %s: %s", resp.status_code, resp.text[:100])
                    return []

                commits_data = resp.json()
                if not commits_data or not isinstance(commits_data, list):
                    return []

                latest_commit = commits_data[0]
                latest_sha = latest_commit.get("sha")

                if not latest_sha:
                    return []

                # Initial baseline: record current commit SHA
                if self._last_commit_sha is None:
                    self._last_commit_sha = latest_sha
                    logger.info("📌 Monitored GitHub repository %s baseline set at commit %s", clean_repo, latest_sha[:8])
                    return []

                # If SHA changed, a new push occurred!
                if latest_sha != self._last_commit_sha:
                    logger.info("⚡ New push detected on GitHub: %s (new commit: %s)", clean_repo, latest_sha[:8])
                    self._last_commit_sha = latest_sha

                    # Fetch detailed commit files
                    detail_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{latest_sha}"
                    detail_resp = await client.get(detail_url, headers=headers)
                    if detail_resp.status_code == 200:
                        detail_data = detail_resp.json()
                        files = detail_data.get("files", [])
                        commit_meta = detail_data.get("commit", {})
                        author = (
                            commit_meta.get("author", {}).get("name")
                            or commit_meta.get("committer", {}).get("name")
                            or "Developer"
                        )
                        msg = commit_meta.get("message") or f"Push commit {latest_sha[:7]}"

                        async with async_session() as session:
                            for f_item in files:
                                fname = f_item.get("filename", "")
                                if not fname.endswith(".py"):
                                    continue
                                status = f_item.get("status", "modified")

                                # Fetch the latest raw content for modified file
                                raw_content = None
                                if status != "removed":
                                    raw_content = await GitMonitorEngine.fetch_remote_file_content(
                                        repository=clean_repo,
                                        file_path=fname,
                                        branch=self._branch,
                                        token=auth_token,
                                    )

                                res = await GitMonitorEngine.process_file_change(
                                    db=session,
                                    repository=clean_repo,
                                    file_path=fname,
                                    content=raw_content,
                                    commit_id=latest_sha,
                                    commit_message=msg,
                                    author=author,
                                    branch=self._branch,
                                    action="removed" if status == "removed" else "modified",
                                    token=auth_token,
                                )
                                results.append(res)

        except Exception as err:
            logger.debug("Error checking remote GitHub repository: %s", err)

        return results

    async def _check_local_filesystem(self) -> List[Dict[str, Any]]:
        """Check local filesystem modification timestamps."""
        from datetime import datetime
        self._last_check_time = datetime.utcnow().isoformat()
        results = []

        if not self._watch_dir or not self._watch_dir.exists():
            return []

        current_index = self._index_files(self._watch_dir)

        # Check for modified or added files
        for fpath, mtime in current_index.items():
            old_mtime = self._file_mtimes.get(fpath)
            if old_mtime is not None and mtime > old_mtime + 0.01:
                rel_path = os.path.relpath(fpath, self._watch_dir)
                logger.info("🔔 Watcher detected edit in %s", rel_path)
                async with async_session() as session:
                    try:
                        res = await GitMonitorEngine.process_file_change(
                            db=session,
                            repository=self._repository_name,
                            file_path=rel_path,
                            commit_message=f"Live Watcher: Modified {rel_path}",
                            action="modified",
                        )
                        results.append(res)
                    except Exception as e:
                        logger.error("Watcher failed to process change in %s: %s", rel_path, e)

            elif old_mtime is None:
                rel_path = os.path.relpath(fpath, self._watch_dir)
                logger.info("🔔 Watcher detected new file %s", rel_path)
                async with async_session() as session:
                    try:
                        res = await GitMonitorEngine.process_file_change(
                            db=session,
                            repository=self._repository_name,
                            file_path=rel_path,
                            commit_message=f"Live Watcher: Added {rel_path}",
                            action="added",
                        )
                        results.append(res)
                    except Exception as e:
                        logger.error("Watcher failed to process new file in %s: %s", rel_path, e)

        # Check for deleted files
        for fpath in list(self._file_mtimes.keys()):
            if fpath not in current_index:
                rel_path = os.path.relpath(fpath, self._watch_dir)
                logger.info("🔔 Watcher detected deleted file %s", rel_path)
                async with async_session() as session:
                    try:
                        res = await GitMonitorEngine.process_file_change(
                            db=session,
                            repository=self._repository_name,
                            file_path=rel_path,
                            commit_message=f"Live Watcher: Removed {rel_path}",
                            action="removed",
                        )
                        results.append(res)
                    except Exception as e:
                        logger.error("Watcher failed to process removed file %s: %s", rel_path, e)

        self._file_mtimes = current_index
        return results

    async def _poll_loop(self):
        while self._is_running:
            try:
                await asyncio.sleep(self._poll_interval)
                if not self._is_running:
                    break

                if self._mode == "remote":
                    await self._check_remote_github()
                elif self._mode == "local" and self._watch_dir:
                    await self._check_local_filesystem()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Error in Live Git Watcher loop: %s", e)


watcher_instance = LiveGitWatcher()
