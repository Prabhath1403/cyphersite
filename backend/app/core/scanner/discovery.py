"""
Discovery engine for DNS resolution, subdomain enumeration, and port scanning.

Uses dnspython for DNS lookups, crt.sh for passive subdomain discovery,
and async socket connections for port scanning to discover all exposed
cryptographic endpoints.
"""

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Set
from urllib.parse import urlsplit

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# Common TLS ports to scan
TLS_PORTS = [443, 8443, 993, 465, 636, 4433, 8080, 8444]

# Expanded subdomain wordlist for brute-force
SUBDOMAIN_WORDLIST = [
    # Infrastructure
    "www", "www2", "www3", "web", "web1", "web2",
    "api", "api2", "api3", "rest", "graphql", "grpc",
    "app", "apps", "application", "mobile", "m",
    # Mail
    "mail", "mail2", "email", "smtp", "imap", "pop", "pop3",
    "mx", "mx1", "mx2", "mx3", "exchange", "webmail", "outlook",
    # Security & Auth
    "auth", "oauth", "sso", "login", "signin", "accounts",
    "secure", "security", "identity", "id", "cas", "adfs",
    # Admin & Management
    "admin", "administrator", "manage", "management",
    "dashboard", "panel", "console", "portal", "cp",
    # Development & CI/CD
    "dev", "dev2", "develop", "staging", "stage", "stg",
    "test", "testing", "qa", "uat", "sandbox",
    "ci", "cd", "jenkins", "gitlab", "github", "build",
    "beta", "alpha", "canary", "preview", "demo",
    # Cloud & Infrastructure
    "cloud", "aws", "azure", "gcp", "k8s",
    "cdn", "edge", "cache", "static", "assets", "media", "images",
    "lb", "load", "proxy", "reverse", "gateway", "gw",
    "vpn", "remote", "rdp", "ssh", "bastion", "jump",
    # Data & Storage
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "sql", "data", "analytics", "warehouse", "elastic", "search",
    "storage", "s3", "blob", "files", "upload",
    # Services
    "dns", "ns", "ns1", "ns2", "ns3", "ns4",
    "ftp", "sftp", "file", "transfer",
    "ldap", "ad", "directory",
    "ntp", "time", "log", "logs", "syslog", "monitor",
    # Communication
    "chat", "meet", "video", "conference", "slack",
    "docs", "wiki", "help", "support", "kb", "faq",
    "blog", "news", "press", "status", "health",
    # Business
    "shop", "store", "ecommerce", "pay", "payment", "billing",
    "crm", "erp", "hr", "internal", "intranet", "corp",
    "partner", "vendor", "client", "customer",
    # Networking
    "router", "switch", "firewall", "waf",
    "vpn1", "vpn2", "tunnel", "ipsec",
    "wifi", "wireless", "radius",
    # Misc
    "info", "about", "careers", "jobs", "investor",
    "survey", "feedback", "report", "track", "tracking",
    "forum", "community", "social",
    "img", "pic", "video", "stream", "live",
    "autodiscover", "autoconfig", "wpad",
    "backup", "bak", "archive", "old", "legacy",
    "new", "next", "v2", "v3",
]

# Service type detection by port
PORT_SERVICE_MAP = {
    443: "web_server",
    8443: "web_server",
    8080: "web_server",
    8444: "api",
    993: "mail",
    465: "mail",
    636: "ldap",
    4433: "vpn",
}

CIDR_HOST_LIMITS = {
    "quick": 64,
    "full": 256,
}


@dataclass
class DiscoveredEndpoint:
    """A discovered cryptographic endpoint."""
    host: str
    ip: str
    port: int
    service_type: str = "other"

    def to_dict(self):
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DiscoveryResult:
    """Results from the discovery phase."""
    target: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    subdomains_found: int = 0
    errors: List[str] = field(default_factory=list)


def normalize_target_input(target: str) -> str:
    """
    Normalize user input into a scanable host target.

    Supports domain/IP input as well as URL-style input such as:
    - https://example.com
    - http://example.com:8443/path
    - example.com/path
    """
    cleaned = (target or "").strip()
    if not cleaned:
        raise ValueError("Target cannot be empty")

    # Preserve CIDR input as-is for host expansion.
    try:
        ipaddress.ip_network(cleaned, strict=False)
        return cleaned
    except ValueError:
        pass

    parsed = urlsplit(cleaned if "://" in cleaned else f"//{cleaned}")
    if parsed.hostname:
        return parsed.hostname.rstrip(".")

    fallback = (
        cleaned.split("/", 1)[0]
        .split("?", 1)[0]
        .split("#", 1)[0]
        .strip()
        .rstrip(".")
    )
    if fallback:
        return fallback

    raise ValueError(f"Invalid target format: {target}")


def _is_ip_or_cidr(target: str) -> bool:
    """Return True when target is an IP address or CIDR range."""
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def _expand_cidr_hosts(target: str, scan_depth: str) -> tuple[List[str], Optional[str]]:
    """
    Expand CIDR targets to a bounded host list.

    Limits are applied by scan depth to avoid unbounded scans.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target], None

    # Single-host network (/32 or /128).
    if network.prefixlen == network.max_prefixlen:
        return [str(network.network_address)], None

    max_hosts = CIDR_HOST_LIMITS.get(scan_depth, CIDR_HOST_LIMITS["quick"])
    hosts = []
    for idx, host in enumerate(network.hosts()):
        if idx >= max_hosts:
            break
        hosts.append(str(host))

    if not hosts:
        hosts = [str(network.network_address)]

    total_hosts = max(network.num_addresses - 2, 1)
    if total_hosts > len(hosts):
        return (
            hosts,
            f"CIDR range truncated to first {len(hosts)} hosts of {total_hosts} "
            f"for {scan_depth} scan depth",
        )

    return hosts, None


async def resolve_dns(domain: str) -> dict:
    """
    Resolve DNS records for a domain.

    Queries A, AAAA, CNAME, and MX records.

    Args:
        domain: The domain to resolve.

    Returns:
        Dictionary of record types to lists of values.
    """
    records = {"A": [], "AAAA": [], "CNAME": [], "MX": []}

    for record_type in records.keys():
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                if record_type == "MX":
                    records[record_type].append({
                        "priority": rdata.preference,
                        "exchange": str(rdata.exchange).rstrip(".")
                    })
                else:
                    records[record_type].append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain} {record_type}: {e}")
            continue

    return records


async def resolve_ip(host: str) -> Optional[str]:
    """
    Resolve a hostname to an IP address.

    Args:
        host: The hostname to resolve.

    Returns:
        The IP address or None if resolution fails.
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyname, host)
        return result
    except socket.gaierror:
        return None


async def scan_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    Check if a specific port is open on a host using async socket connection.

    Args:
        host: Target hostname or IP.
        port: Port number to check.
        timeout: Connection timeout in seconds.

    Returns:
        True if the port is open, False otherwise.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def scan_ports(host: str, ports: List[int] = None) -> List[int]:
    """
    Scan multiple ports on a host concurrently.

    Args:
        host: Target hostname or IP.
        ports: List of ports to scan. Defaults to TLS_PORTS.

    Returns:
        List of open port numbers.
    """
    if ports is None:
        ports = TLS_PORTS

    tasks = [scan_port(host, port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_ports = []
    for port, is_open in zip(ports, results):
        if isinstance(is_open, bool) and is_open:
            open_ports.append(port)

    return open_ports


async def discover_subdomains_passive(domain: str) -> Set[str]:
    """
    Discover subdomains passively using Certificate Transparency logs (crt.sh).

    This queries publicly logged TLS certificates to find all subdomains
    that have had certificates issued for them. Much more comprehensive
    than brute force.

    Args:
        domain: The base domain to enumerate subdomains for.

    Returns:
        Set of discovered subdomain FQDNs.
    """
    discovered = set()

    try:
        import aiohttp

        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        # crt.sh returns newline-separated names
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            # Skip wildcards and non-matching domains
                            if name.startswith("*."):
                                name = name[2:]
                            if name.endswith(f".{domain}") or name == domain:
                                discovered.add(name)

        logger.info(f"crt.sh passive discovery found {len(discovered)} subdomains for {domain}")

    except ImportError:
        logger.warning("aiohttp not available, skipping passive subdomain discovery")
    except Exception as e:
        logger.warning(f"crt.sh passive discovery failed for {domain}: {e}")

    return discovered


async def discover_subdomains_bruteforce(domain: str) -> Set[str]:
    """
    Discover subdomains using DNS brute force with the expanded wordlist.

    Args:
        domain: The base domain to enumerate subdomains for.

    Returns:
        Set of discovered subdomains that resolve.
    """
    discovered = set()
    semaphore = asyncio.Semaphore(50)  # Limit concurrent DNS queries

    async def check_subdomain(sub: str):
        async with semaphore:
            fqdn = f"{sub}.{domain}"
            ip = await resolve_ip(fqdn)
            if ip:
                discovered.add(fqdn)

    tasks = [check_subdomain(sub) for sub in SUBDOMAIN_WORDLIST]
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info(f"Brute force discovery found {len(discovered)} subdomains for {domain}")
    return discovered


def classify_service(port: int) -> str:
    """
    Classify the service type based on the port number.

    Args:
        port: The port number.

    Returns:
        Service type string.
    """
    return PORT_SERVICE_MAP.get(port, "other")


async def run_discovery(target: str, scan_depth: str = "quick") -> DiscoveryResult:
    """
    Run the full discovery process for a target.

    Steps:
    1. DNS resolution for the target
    2. Subdomain enumeration (if full scan):
       - Passive via Certificate Transparency (crt.sh)
       - Active via DNS brute force with expanded wordlist
    3. Port scanning on all discovered hosts
    4. Service classification

    Args:
        target: Domain, IP, or hostname to scan.
        scan_depth: 'quick' for target only, 'full' for subdomain enum too.

    Returns:
        DiscoveryResult with all discovered endpoints.
    """
    result = DiscoveryResult(target=target)

    try:
        normalized_target = normalize_target_input(target)
    except ValueError as e:
        result.errors.append(str(e))
        logger.error("Invalid discovery target '%s': %s", target, e)
        return result

    hosts_to_scan_list, cidr_warning = _expand_cidr_hosts(normalized_target, scan_depth)
    hosts_to_scan: Set[str] = set(hosts_to_scan_list)
    if cidr_warning:
        result.errors.append(cidr_warning)
        logger.warning(cidr_warning)

    # Step 1: DNS resolution
    if not _is_ip_or_cidr(normalized_target):
        try:
            result.dns_records = await resolve_dns(normalized_target)
            logger.info(f"DNS records for {normalized_target}: {result.dns_records}")
        except Exception as e:
            result.errors.append(f"DNS resolution failed: {str(e)}")
            logger.error(f"DNS resolution failed for {normalized_target}: {e}")

    # Step 2: Subdomain enumeration (full scan only)
    if scan_depth == "full" and not _is_ip_or_cidr(normalized_target):
        try:
            # Run passive (crt.sh) and active (brute force) in parallel
            passive_task = discover_subdomains_passive(normalized_target)
            active_task = discover_subdomains_bruteforce(normalized_target)

            passive_results, active_results = await asyncio.gather(
                passive_task, active_task, return_exceptions=True
            )

            # Merge results
            if isinstance(passive_results, set):
                hosts_to_scan.update(passive_results)
            else:
                logger.warning(f"Passive subdomain discovery error: {passive_results}")

            if isinstance(active_results, set):
                hosts_to_scan.update(active_results)
            else:
                logger.warning(f"Active subdomain discovery error: {active_results}")

            result.subdomains_found = len(hosts_to_scan) - 1  # Minus the original target
            logger.info(f"Total unique hosts to scan: {len(hosts_to_scan)}")

        except Exception as e:
            result.errors.append(f"Subdomain enumeration failed: {str(e)}")

    # Step 3: Scan ports on each host
    # Use semaphore to limit concurrent port scans
    scan_semaphore = asyncio.Semaphore(20)

    async def scan_host(host: str):
        async with scan_semaphore:
            try:
                ip = await resolve_ip(host)
                if not ip:
                    logger.debug(f"Could not resolve IP for {host}")
                    return []

                open_ports = await scan_ports(host)
                logger.info(f"Open ports on {host}: {open_ports}")

                endpoints = []
                for port in open_ports:
                    endpoint = DiscoveredEndpoint(
                        host=host,
                        ip=ip,
                        port=port,
                        service_type=classify_service(port),
                    )
                    endpoints.append(endpoint)
                return endpoints

            except Exception as e:
                result.errors.append(f"Port scan failed for {host}: {str(e)}")
                logger.error(f"Port scan error for {host}: {e}")
                return []

    # Scan all hosts concurrently
    scan_tasks = [scan_host(host) for host in hosts_to_scan]
    all_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

    for host_endpoints in all_results:
        if isinstance(host_endpoints, list):
            result.endpoints.extend(host_endpoints)

    # Deduplicate endpoints by (host, port) tuple
    seen = set()
    unique_endpoints = []
    for ep in result.endpoints:
        key = (ep.host, ep.port)
        if key not in seen:
            seen.add(key)
            unique_endpoints.append(ep)
    result.endpoints = unique_endpoints

    # If no ports were found open, add default port 443 for single-host targets.
    if not result.endpoints and len(hosts_to_scan) == 1:
        fallback_host = list(hosts_to_scan)[0]
        ip = await resolve_ip(fallback_host)
        if ip:
            result.endpoints.append(DiscoveredEndpoint(
                host=fallback_host,
                ip=ip,
                port=443,
                service_type="web_server",
            ))

    logger.info(f"Discovery complete: {len(result.endpoints)} endpoints, "
                f"{result.subdomains_found} subdomains for {target}")

    return result
