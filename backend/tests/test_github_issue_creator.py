"""
Tests for GitHub Issue Creation and Developer Remediation API endpoints.
"""

import pytest
from app.core.source_scanner import CryptoFindingData
from app.core.github import GitHubIssueCreator, GitHubIssuePayload


def test_generate_issue_for_rsa():
    """Test generating a rich GitHub Issue markdown payload for an RSA finding."""
    finding = CryptoFindingData(
        name="RSA-2048 JWT Signer",
        asset_type="source_code_usage",
        source_type="source_code",
        algorithm="RSA-2048",
        file_path="/app/security/jwt.py",
        line_number=42,
        function_name="create_token",
        sensitivity="CRITICAL",
        risk_score=90.0,
    )
    issue = GitHubIssueCreator.generate_issue_for_finding(finding)

    assert "Upgrade RSA-2048 to ML-DSA-65" in issue.title
    assert "jwt.py:L42" in issue.title
    assert "security" in issue.labels
    assert "p0_critical" in issue.labels

    # Check Markdown body
    assert "### 🛡️ Post-Quantum Security Remediation" in issue.body
    assert "ML-DSA-65" in issue.body
    assert "```python" in issue.body
    assert "- [ ]" in issue.body


@pytest.mark.asyncio
async def test_remediation_api_endpoints(client, tmp_path):
    """Test /api/remediation endpoints with a real scan in the DB."""
    # 1. Run source scan to populate DB
    py_file = tmp_path / "auth_module.py"
    py_file.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(65537, 2048)\n"
    )

    scan_resp = await client.post(
        "/api/scan/source",
        json={"path": str(tmp_path), "scan_depth": "standard"},
    )
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    scan_id = scan_data["id"]
    finding_id = scan_data["findings"][0]["id"]

    # 2. Preview issue for specific finding
    preview_resp = await client.get(f"/api/remediation/finding/{finding_id}/issue-preview")
    assert preview_resp.status_code == 200
    preview_data = preview_resp.json()
    assert "title" in preview_data
    assert "body" in preview_data
    assert "labels" in preview_data
    assert "Post-Quantum" in preview_data["body"]

    # 3. Export all scan issues
    export_resp = await client.get(f"/api/remediation/scan/{scan_id}/export-issues")
    assert export_resp.status_code == 200
    export_data = export_resp.json()
    assert export_data["total_issues"] >= 1
    assert len(export_data["issues"]) >= 1
