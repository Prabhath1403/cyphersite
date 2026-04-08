"""
API endpoint HTTPS probing module.

Probes HTTP/HTTPS endpoints to detect API services and
extract security headers.
"""

import asyncio
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class APIProbeResult:
    """Result of probing an API/web endpoint."""
    url: str = ""
    status_code: int = 0
    server_header: str = ""
    security_headers: Dict[str, str] = field(default_factory=dict)
    is_api: bool = False
    content_type: str = ""
    redirect_url: Optional[str] = None
    errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# Security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


async def probe_endpoint(host: str, port: int = 443, path: str = "/") -> APIProbeResult:
    """
    Probe an HTTP/HTTPS endpoint for API characteristics.

    Args:
        host: Target hostname.
        port: Target port.
        path: Path to probe.

    Returns:
        APIProbeResult with detected information.
    """
    scheme = "https" if port in (443, 8443, 8444) else "http"
    url = f"{scheme}://{host}:{port}{path}"
    result = APIProbeResult(url=url)

    try:
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(url, allow_redirects=False) as response:
                result.status_code = response.status
                result.server_header = response.headers.get("Server", "")
                result.content_type = response.headers.get("Content-Type", "")

                # Check for API indicators
                if "application/json" in result.content_type:
                    result.is_api = True
                elif "application/xml" in result.content_type:
                    result.is_api = True

                # Collect security headers
                for header in SECURITY_HEADERS:
                    value = response.headers.get(header)
                    if value:
                        result.security_headers[header] = value

                # Check redirect
                if response.status in (301, 302, 307, 308):
                    result.redirect_url = response.headers.get("Location", "")

    except aiohttp.ClientError as e:
        result.errors.append(f"HTTP probe failed: {str(e)}")
        logger.debug(f"Probe failed for {url}: {e}")
    except asyncio.TimeoutError:
        result.errors.append("Connection timed out")
    except Exception as e:
        result.errors.append(f"Unexpected error: {str(e)}")
        logger.error(f"Probe error for {url}: {e}")

    return result


async def probe_common_api_paths(host: str, port: int = 443) -> list:
    """
    Probe common API paths to detect API services.

    Args:
        host: Target hostname.
        port: Target port.

    Returns:
        List of APIProbeResult for paths that responded.
    """
    common_paths = [
        "/",
        "/api",
        "/api/v1",
        "/api/v2",
        "/health",
        "/healthz",
        "/status",
        "/.well-known/openid-configuration",
        "/swagger.json",
        "/openapi.json",
    ]

    tasks = [probe_endpoint(host, port, path) for path in common_paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid_results = []
    for r in results:
        if isinstance(r, APIProbeResult) and r.status_code > 0:
            valid_results.append(r)

    return valid_results
