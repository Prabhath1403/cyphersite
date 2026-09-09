"""
Tests for GitHub repository fetcher and GitHub scanning endpoints.
"""

import io
import os
import shutil
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.core.github.repository_fetcher import GitHubRepositoryFetcher


def test_parse_github_url():
    """Test URL and shorthand parsing for various GitHub repository references."""
    # HTTPS
    owner, repo = GitHubRepositoryFetcher.parse_github_url("https://github.com/psf/requests")
    assert owner == "psf"
    assert repo == "requests"

    # HTTPS with .git
    owner, repo = GitHubRepositoryFetcher.parse_github_url("https://github.com/pallets/flask.git")
    assert owner == "pallets"
    assert repo == "flask"

    # SSH
    owner, repo = GitHubRepositoryFetcher.parse_github_url("git@github.com:torvalds/linux.git")
    assert owner == "torvalds"
    assert repo == "linux"

    # Shorthand owner/repo
    owner, repo = GitHubRepositoryFetcher.parse_github_url("fastapi/fastapi")
    assert owner == "fastapi"
    assert repo == "fastapi"


def test_parse_github_url_invalid():
    """Test invalid targets raise ValueError."""
    with pytest.raises(ValueError):
        GitHubRepositoryFetcher.parse_github_url("not-a-repo")

    with pytest.raises(ValueError):
        GitHubRepositoryFetcher.parse_github_url("a/b/c/d")


@pytest.mark.asyncio
async def test_get_repository_info_success():
    """Test fetching repository metadata from mocked GitHub API."""
    mock_payload = {
        "full_name": "psf/requests",
        "default_branch": "main",
        "description": "A simple, yet elegant, HTTP library.",
        "stargazers_count": 52000,
        "forks_count": 9200,
        "private": False,
        "language": "Python",
        "size": 14200,
        "clone_url": "https://github.com/psf/requests.git",
        "html_url": "https://github.com/psf/requests",
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_payload

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        info = await GitHubRepositoryFetcher.get_repository_info("psf", "requests")
        assert info["owner"] == "psf"
        assert info["repo"] == "requests"
        assert info["stars"] == 52000
        assert info["language"] == "Python"
        assert info["default_branch"] == "main"
        assert info["is_private"] is False


@pytest.mark.asyncio
async def test_get_repository_info_not_found():
    """Test 404 response raises appropriate ValueError."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        with pytest.raises(ValueError, match="not found on GitHub"):
            await GitHubRepositoryFetcher.get_repository_info("nonexistent", "repo")


@pytest.mark.asyncio
async def test_fetch_codebase_zipball(tmp_path):
    """Test extracting codebase via in-memory zipball without git CLI."""
    # Create an in-memory zip buffer simulating GitHub's zipball format
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        # GitHub archives nest files inside a root folder: owner-repo-sha/
        zf.writestr(
            "testowner-testrepo-abc1234/crypto_service.py",
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(65537, 2048)\n",
        )
        zf.writestr("testowner-testrepo-abc1234/README.md", "# Test Repo\n")
    zip_bytes = zip_buf.getvalue()

    # Mock get_repository_info
    mock_meta = {
        "owner": "testowner",
        "repo": "testrepo",
        "default_branch": "main",
        "stars": 10,
        "language": "Python",
    }

    mock_zip_resp = MagicMock()
    mock_zip_resp.status_code = 200
    mock_zip_resp.content = zip_bytes

    with patch.object(GitHubRepositoryFetcher, "get_repository_info", return_value=mock_meta):
        with patch("httpx.AsyncClient.get", return_value=mock_zip_resp):
            extracted_dir, repo_name, meta = await GitHubRepositoryFetcher.fetch_codebase(
                "testowner/testrepo",
                dest_dir=str(tmp_path / "dest"),
            )

            assert repo_name == "testowner/testrepo"
            assert os.path.exists(extracted_dir)
            assert os.path.exists(os.path.join(extracted_dir, "crypto_service.py"))
            assert os.path.exists(os.path.join(extracted_dir, "README.md"))


@pytest.mark.asyncio
async def test_github_api_endpoints(client, tmp_path):
    """Test /api/scan/github/info and /api/scan/github endpoints."""
    # 1. Test /api/scan/github/info
    mock_meta = {
        "owner": "testowner",
        "repo": "testrepo",
        "full_name": "testowner/testrepo",
        "default_branch": "main",
        "description": "Mocked Repo",
        "stars": 42,
        "forks": 5,
        "is_private": False,
        "language": "Python",
        "size_kb": 1024,
        "clone_url": "https://github.com/testowner/testrepo.git",
        "html_url": "https://github.com/testowner/testrepo",
    }
    with patch.object(GitHubRepositoryFetcher, "get_repository_info", return_value=mock_meta):
        resp = await client.get("/api/scan/github/info?url=https://github.com/testowner/testrepo")
        assert resp.status_code == 200
        data = resp.json()
        assert data["stars"] == 42
        assert data["language"] == "Python"
        assert data["default_branch"] == "main"

    # 2. Test /api/scan/github scanning execution
    mock_target_dir = tmp_path / "mock_gh_repo"
    mock_target_dir.mkdir()
    (mock_target_dir / "service.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(65537, 2048)\n"
    )

    with patch.object(
        GitHubRepositoryFetcher,
        "fetch_codebase",
        return_value=(str(mock_target_dir), "testowner/testrepo", mock_meta),
    ):
        scan_resp = await client.post(
            "/api/scan/github",
            json={
                "url": "https://github.com/testowner/testrepo",
                "branch": "main",
                "scan_depth": "standard",
            },
        )
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()
        assert scan_data["status"] == "completed"
        assert scan_data["total_assets"] >= 1
        assert scan_data["vulnerable_count"] >= 1
        assert any("RSA" in f["algorithm"] for f in scan_data["findings"])
