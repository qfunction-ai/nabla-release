"""SSRF URL validation — block private IPs, localhost, and invalid schemes.

Used by connectors to validate the configured host URL before making
any outbound requests.

Provides two layers of defense:
1. Pre-request DNS validation (catches obvious private IPs)
2. Post-connection peer IP validation (catches DNS rebinding / TOCTOU)

Also provides safe redirect following that validates each hop.
"""

import ipaddress
import socket
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:
    pass

from nabla.log import get_logger

logger = get_logger("ssrf")

# Private/reserved IP ranges that should never be reachable from a connector
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(ip_str: str) -> bool:
    """R6-13 (round 6): an address is private/reserved by its ipaddress
    PROPERTIES, with explicit unwrapping of the IPv4-embedding forms the
    property checks miss:

    - IPv4-mapped IPv6 (::ffff:169.254.169.254) — .is_private is True on
      some versions but the old NETWORK-LIST check missed it entirely
      (verified live: ALLOWED);
    - NAT64 (64:ff9b::/96) and 6to4 (2002::/16) — embed IPv4; the
      properties know nothing about the embedded address.

    The hand-written _PRIVATE_NETWORKS list is retired: it missed
    0.0.0.0/8, 100.64.0.0/10, ::/128, and every embedding form.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # Unwrap IPv4-embedding forms to the embedded IPv4 and check THAT
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            addr = mapped
        elif addr in ipaddress.ip_network("64:ff9b::/96"):  # NAT64
            embedded = int(addr) & 0xFFFFFFFF
            addr = ipaddress.IPv4Address(embedded)
        elif addr in ipaddress.ip_network("2002::/16"):     # 6to4
            embedded = (int(addr) >> 48) & 0xFFFFFFFF
            addr = ipaddress.IPv4Address(embedded)
    # 100.64.0.0/10 (CGNAT/shared address space) has no stdlib property
    # but reaches local interfaces on many hosts — explicit (R6-13)
    _cgnat = ipaddress.ip_network("100.64.0.0/10")
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_unspecified
            or addr.is_multicast or addr in _cgnat)


def validate_connector_url(url: str) -> tuple[bool, str]:
    """Validate a SIEM connector URL for SSRF safety.

    Checks:
    - Scheme must be http or https
    - Hostname must not resolve to a private IP
    - Hostname must not be localhost or a bare IP in a private range
    - Hostname must be resolvable

    Args:
        url: The connector base URL (e.g., "https://splunk.example.com:8089").

    Returns:
        (is_valid, error_message) — error_message is empty when valid.
    """
    parsed = urlparse(url)

    # Scheme check
    if parsed.scheme not in ("http", "https"):
        return False, f"Invalid scheme '{parsed.scheme}' — only http and https are allowed"

    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no hostname"

    # Check for localhost variants
    if hostname in ("localhost", "localhost.localdomain"):
        return False, "localhost is not allowed — use a real hostname"
    # R6-13: bracketed IPv6 literals ([::ffff:...]) — urlparse's hostname
    # strips the brackets; the property check below catches the unwrapped
    # form.

    # Check if hostname is a bare IP
    try:
        ip = ipaddress.ip_address(hostname)
        if _is_private_ip(str(ip)):
            return False, f"IP address {ip} is in a private/reserved range"
    except ValueError:
        pass  # silent by design: not an IP literal, proceeds to DNS resolution (2026-09 sweep)

    # DNS resolution check
    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return False, f"Hostname '{hostname}' does not resolve"

    # Check all resolved IPs for private ranges
    for family, _, _, _, sockaddr in resolved:
        ip_str = sockaddr[0]
        if _is_private_ip(ip_str):
            return False, f"Hostname '{hostname}' resolves to private IP {ip_str}"

    return True, ""


def verify_dns_stability(hostname: str, original_ips: set[str]) -> tuple[bool, str]:
    """Re-resolve a hostname and check if IPs changed (DNS rebinding detection).

    Called after the first successful request to detect if DNS resolution
    has changed between the pre-request validation and the actual connection.
    This narrows the TOCTOU window for DNS rebinding attacks.

    Args:
        hostname: The hostname to re-resolve.
        original_ips: The set of IPs returned by the initial DNS resolution.

    Returns:
        (is_stable, error_message) — error_message is empty when stable.
    """
    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return False, f"DNS re-check: hostname '{hostname}' no longer resolves"

    current_ips = set()
    for family, _, _, _, sockaddr in resolved:
        current_ips.add(sockaddr[0])

    if not current_ips:
        return False, f"DNS re-check: hostname '{hostname}' resolved to no IPs"

    # Check if any new IPs are private (DNS could have changed to private)
    for ip_str in current_ips:
        if _is_private_ip(ip_str):
            return False, (
                f"DNS re-check: hostname '{hostname}' now resolves to private IP {ip_str} "
                f"(possible DNS rebinding)"
            )

    # Check if the IP set has changed significantly
    if original_ips and current_ips != original_ips:
        new_ips = current_ips - original_ips
        if new_ips:
            logger.warning(
                "DNS resolution changed for '%s': original=%s, current=%s",
                hostname, original_ips, current_ips,
            )

    return True, ""


def follow_redirects_safe(
    client: httpx.Client,
    response: httpx.Response,
    original_hostname: str = "",
    max_redirects: int = 5,
    caller_name: str = "connector",
) -> httpx.Response:
    """Manually follow HTTP redirects with SSRF validation on each hop.

    httpx with follow_redirects=False returns 3xx responses directly.
    This function follows them while validating each redirect target
    against SSRF rules (when original_hostname is provided).

    Args:
        client: The httpx client (must have follow_redirects=False).
        response: The initial response (may be a 3xx redirect).
        original_hostname: The hostname from the original URL (for SSRF checks).
        max_redirects: Maximum number of redirects to follow.
        caller_name: Name for error messages (e.g., "Splunk", "SumoLogic").

    Returns:
        The final non-redirect response.

    Raises:
        ValueError: If a redirect target fails SSRF validation or
            too many redirects are encountered.
    """
    for _ in range(max_redirects):
        if response.status_code not in (301, 302, 303, 307, 308):
            return response

        location = response.headers.get("location")
        if not location:
            return response

        # Validate redirect target against SSRF rules. Round-7 low: the
        # relative-URL branch rebuilds the absolute form with the
        # ORIGINAL request's scheme — hardcoding https would turn an
        # http-only internal service into a failed redirect follow.
        if original_hostname:
            original_scheme = str(response.url.scheme) if response.url else "https"
            is_valid, err = validate_redirect_url(location, original_hostname,
                                                  original_scheme=original_scheme)
            if not is_valid:
                raise ValueError(f"{caller_name} redirect blocked: {err}")

        logger.debug("Following redirect: %s -> %s", response.url, location)
        response = client.send(
            response.next if response.next else client.build_request("GET", location),
            stream=False,
        )

    raise ValueError(f"Too many redirects (>{max_redirects}) from {caller_name} host")


def follow_get_redirects_safe(
    url: str,
    allowed_hosts: tuple[str, ...] | None = None,
    max_redirects: int = 5,
    timeout: float = 120.0,
    caller_name: str = "download",
) -> httpx.Response:
    """Follow redirects for a bare httpx.get() with host-whitelist validation.

    Used by download+cache functions (ATT&CK, LOLBAS) that don't use
    a persistent httpx.Client. Instead of SSRF IP validation, validates
    redirect targets against an allowed-hosts whitelist.

    Args:
        url: The initial URL to fetch.
        allowed_hosts: Tuple of allowed hostnames for redirects (e.g.,
            ("github.com", "raw.githubusercontent.com")). If None, all
            redirects are allowed (not recommended).
        max_redirects: Maximum number of redirects to follow.
        timeout: Request timeout in seconds.
        caller_name: Name for error messages.

    Returns:
        The final response (non-redirect).

    Raises:
        ValueError: If a redirect target is not in allowed_hosts or
            too many redirects are encountered.
    """
    resp = httpx.get(url, timeout=timeout, follow_redirects=False)

    for _ in range(max_redirects):
        if resp.status_code not in (301, 302, 303, 307, 308):
            break
        location = resp.headers.get("location", "")
        if not location:
            break
        if allowed_hosts:
            parsed_loc = urlparse(location)
            loc_host = (parsed_loc.hostname or "").lower()
            if loc_host not in allowed_hosts:
                logger.warning(
                    "%s redirect to unexpected host '%s' blocked", caller_name, loc_host
                )
                raise ValueError(
                    f"{caller_name} redirect to unexpected host '{loc_host}' blocked"
                )
        logger.debug("Following %s redirect: %s", caller_name, location)
        resp = httpx.get(location, timeout=timeout, follow_redirects=False)

    return resp


def validate_redirect_url(redirect_url: str, original_hostname: str,
                          original_scheme: str = "https") -> tuple[bool, str]:
    """Validate a redirect URL against SSRF rules.

    Prevents redirect-based SSRF where the initial request goes to a
    valid host but the server redirects to an internal address.

    Args:
        redirect_url: The URL from the Location header.
        original_hostname: The hostname of the original request (for logging).

    Returns:
        (is_valid, error_message) — error_message is empty when valid.
    """
    # Round-6 low: RELATIVE Location headers are legal (RFC 7231) and
    # resolve against the original host — no new SSRF surface (same host
    # already validated). Parse the absolute form and continue — with the
    # ORIGINAL scheme (round-7 low: https was hardcoded).
    if redirect_url.startswith("/") and not redirect_url.startswith("//"):
        redirect_url = f"{original_scheme}://{original_hostname}{redirect_url}"
    elif redirect_url.startswith("//"):
        return False, "protocol-relative redirect blocked (authority change)"

    parsed = urlparse(redirect_url)

    if parsed.scheme not in ("http", "https"):
        return False, f"Redirect to invalid scheme '{parsed.scheme}' blocked"

    hostname = parsed.hostname
    if not hostname:
        return False, "Redirect URL has no hostname"

    # Block localhost
    if hostname in ("localhost", "localhost.localdomain"):
        return False, f"Redirect to localhost blocked (from {original_hostname})"

    # Block bare private IPs
    try:
        ip = ipaddress.ip_address(hostname)
        if _is_private_ip(str(ip)):
            return False, f"Redirect to private IP {ip} blocked (from {original_hostname})"
    except ValueError:
        pass  # silent by design: unparseable URL fails validation by absence (2026-09 sweep)

    # Resolve and check DNS
    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return False, f"Redirect hostname '{hostname}' does not resolve"

    for family, _, _, _, sockaddr in resolved:
        ip_str = sockaddr[0]
        if _is_private_ip(ip_str):
            return False, f"Redirect hostname '{hostname}' resolves to private IP {ip_str}"

    return True, ""
