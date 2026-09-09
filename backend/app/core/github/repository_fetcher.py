"""
GitHub Repository Fetcher & Codebase Extraction Engine.

Provides dual-mode repository retrieval:
1. GitHub API archive (zipball) download via HTTP (daemonless, no git client required).
2. Git clone with token authentication fallback.
"""

from __future__ import annotations

import io
import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class GitHubRepositoryFetcher:
    """Fetches remote GitHub repositories for static analysis."""

    @classmethod
    def parse_github_url(cls, target: str) -> Tuple[str, str]:
        """
        Extract (owner, repo) from various GitHub URL formats or shorthands.

        Examples:
        - https://github.com/pallets/flask
        - https://github.com/pallets/flask.git
        - git@github.com:pallets/flask.git
        - pallets/flask
        """
        raw = target.strip()

        # Remove trailing .git
        if raw.endswith(".git"):
            raw = raw[:-4]

        # Check git@github.com:owner/repo
        ssh_match = re.match(r"^git@github\.com:([\w\-\.]+)/([\w\-\.]+)$", raw)
        if ssh_match:
            return ssh_match.group(1), ssh_match.group(2)

        # Check https://github.com/owner/repo or http://
        http_match = re.search(r"github\.com/([\w\-\.]+)/([\w\-\.]+)", raw)
        if http_match:
            return http_match.group(1), http_match.group(2)

        # Check shorthand owner/repo
        shorthand_match = re.match(r"^([\w\-\.]+)/([\w\-\.]+)$", raw)
        if shorthand_match:
            return shorthand_match.group(1), shorthand_match.group(2)

        raise ValueError(f"Could not parse GitHub owner/repo from '{target}'")

    @classmethod
    async def get_repository_info(
        cls,
        owner: str,
        repo: str,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch repository metadata from the GitHub REST API."""
        auth_token = token or settings.GITHUB_TOKEN
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CipherSight-PQC-Scanner",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        url = f"https://api.github.com/repos/{owner}/{repo}"

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "owner": owner,
                    "repo": repo,
                    "full_name": data.get("full_name", f"{owner}/{repo}"),
                    "default_branch": data.get("default_branch", "main"),
                    "description": data.get("description"),
                    "stars": data.get("stargazers_count", 0),
                    "forks": data.get("forks_count", 0),
                    "is_private": data.get("private", False),
                    "language": data.get("language"),
                    "size_kb": data.get("size", 0),
                    "clone_url": data.get("clone_url"),
                    "html_url": data.get("html_url"),
                }
            elif resp.status_code == 404:
                raise ValueError(
                    f"Repository '{owner}/{repo}' not found on GitHub. "
                    "If this is a private repository, please provide a GitHub Personal Access Token."
                )
            elif resp.status_code == 401:
                raise ValueError("Invalid or expired GitHub Personal Access Token.")
            elif resp.status_code == 403:
                raise ValueError(
                    f"GitHub API rate limit exceeded or access forbidden: {resp.text}"
                )
            else:
                raise RuntimeError(
                    f"GitHub API returned error {resp.status_code}: {resp.text}"
                )

    @classmethod
    async def fetch_codebase(
        cls,
        target: str,
        branch: Optional[str] = None,
        token: Optional[str] = None,
        dest_dir: Optional[str] = None,
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Download and extract a GitHub repository codebase into a local directory.

        Returns:
            Tuple of (extracted_code_dir, repo_name, repo_metadata)
        """
        owner, repo = cls.parse_github_url(target)
        auth_token = token or settings.GITHUB_TOKEN

        # Fetch metadata first
        meta: Dict[str, Any] = {}
        try:
            meta = await cls.get_repository_info(owner, repo, token=auth_token)
            target_branch = branch or meta.get("default_branch", "main")
        except Exception as e:
            logger.warning("Failed to fetch repository metadata via API: %s", e)
            target_branch = branch or "main"

        out_dir = dest_dir or tempfile.mkdtemp(prefix=f"ciphersight_gh_{owner}_{repo}_")

        # ── Strategy 1: GitHub API Zipball Download (No Git CLI required) ──
        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{target_branch}"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CipherSight-PQC-Scanner",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        download_success = False
        try:
            logger.info("Attempting GitHub API zipball download for %s/%s (%s)", owner, repo, target_branch)
            async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
                resp = await client.get(zip_url, headers=headers)
                if resp.status_code == 200 and len(resp.content) > 0:
                    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                        zf.extractall(out_dir)

                    # GitHub zipballs wrap contents in a single top-level folder: owner-repo-hash/
                    extracted_entries = os.listdir(out_dir)
                    if len(extracted_entries) == 1:
                        nested_root = os.path.join(out_dir, extracted_entries[0])
                        if os.path.isdir(nested_root):
                            out_dir = nested_root

                    download_success = True
                    logger.info("Successfully extracted GitHub zipball into %s", out_dir)
                else:
                    logger.warning(
                        "GitHub zipball download returned %s: %s",
                        resp.status_code,
                        resp.text[:200],
                    )
        except Exception as e:
            logger.warning("GitHub API zipball download failed: %s", e)

        # ── Strategy 2: Git Clone Fallback ──
        if not download_success:
            logger.info("Falling back to git clone for %s/%s", owner, repo)
            if auth_token:
                clone_url = f"https://x-access-token:{auth_token}@github.com/{owner}/{repo}.git"
            else:
                clone_url = f"https://github.com/{owner}/{repo}.git"

            clone_dir = tempfile.mkdtemp(prefix=f"ciphersight_git_{repo}_")
            cmd = ["git", "clone", "--depth", "1"]
            if target_branch:
                cmd.extend(["-b", target_branch])
            cmd.extend([clone_url, clone_dir])

            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120)
                out_dir = clone_dir
                download_success = True
            except (subprocess.SubprocessError, FileNotFoundError) as err:
                raise RuntimeError(
                    f"Could not retrieve repository from GitHub via API or Git CLI. "
                    f"Ensure repository exists and credentials are valid: {err}"
                )

        return out_dir, f"{owner}/{repo}", meta
