"""
Core scanning engine.

Implements TCP Connect scanning with multi-threaded execution using
concurrent.futures.ThreadPoolExecutor. Each port is probed independently,
and results are reported in real-time via a callback mechanism.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Optional

from .models import PortResult, PortStatus, ScanReport

# Common port-to-service mapping for well-known ports
WELL_KNOWN_SERVICES: dict[int, str] = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP (Submission)",
    631: "IPP (CUPS)",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "MS SQL",
    1434: "MS SQL Monitor",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8888: "HTTP Alt",
    9090: "Prometheus",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def resolve_target(target: str) -> str:
    """Resolve a hostname to its IP address.

    Args:
        target: Hostname or IP address string.

    Returns:
        The resolved IPv4 address as a string.

    Raises:
        socket.gaierror: If the hostname cannot be resolved.
    """
    return socket.gethostbyname(target)


def get_service_name(port: int) -> str:
    """Look up the well-known service name for a port.

    First checks the built-in mapping, then falls back to the OS
    services database via socket.getservbyport().

    Args:
        port: The port number to look up.

    Returns:
        The service name, or an empty string if unknown.
    """
    if port in WELL_KNOWN_SERVICES:
        return WELL_KNOWN_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def grab_banner(sock: socket.socket, timeout: float = 2.0) -> str:
    """Attempt to read a service banner from an open socket.

    Some services (SSH, FTP, SMTP, etc.) send a banner immediately
    upon connection. This function tries to capture that data.

    Args:
        sock: An already-connected socket.
        timeout: Seconds to wait for banner data.

    Returns:
        The decoded banner string (stripped), or empty string on failure.
    """
    try:
        sock.settimeout(timeout)
        banner = sock.recv(1024)
        return banner.decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError, UnicodeDecodeError):
        return ""


def scan_port(
    target_ip: str,
    port: int,
    timeout: float = 1.5,
    grab_banners: bool = False,
) -> PortResult:
    """Scan a single port using TCP Connect method.

    Creates a full TCP three-way handshake to determine port status:
      - OPEN:     Connection succeeds (SYN → SYN-ACK → ACK).
      - CLOSED:   Connection refused (RST received).
      - FILTERED: Connection times out (no response, likely firewalled).

    Args:
        target_ip: The resolved IP address to scan.
        port: The port number to probe.
        timeout: Connection timeout in seconds.
        grab_banners: Whether to attempt banner grabbing on open ports.

    Returns:
        A PortResult with the determined status and metadata.
    """
    service = get_service_name(port)
    start = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result_code = sock.connect_ex((target_ip, port))
            elapsed_ms = (time.perf_counter() - start) * 1000

            if result_code == 0:
                banner = ""
                if grab_banners:
                    banner = grab_banner(sock)
                return PortResult(
                    port=port,
                    status=PortStatus.OPEN,
                    service=service,
                    banner=banner,
                    response_time_ms=round(elapsed_ms, 2),
                )
            else:
                return PortResult(
                    port=port,
                    status=PortStatus.CLOSED,
                    service=service,
                    response_time_ms=round(elapsed_ms, 2),
                )

    except socket.timeout:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return PortResult(
            port=port,
            status=PortStatus.FILTERED,
            service=service,
            response_time_ms=round(elapsed_ms, 2),
        )
    except OSError:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return PortResult(
            port=port,
            status=PortStatus.FILTERED,
            service=service,
            response_time_ms=round(elapsed_ms, 2),
        )


def run_scan(
    target: str,
    start_port: int = 1,
    end_port: int = 1024,
    threads: int = 200,
    timeout: float = 1.5,
    grab_banners: bool = False,
    on_result: Optional[Callable[[PortResult, int, int], None]] = None,
    show_all: bool = False,
) -> ScanReport:
    """Execute a full port scan across the specified range.

    Distributes port scanning work across a thread pool for concurrent
    execution. Results are reported in real-time via the on_result callback.

    Args:
        target: Hostname or IP address to scan.
        start_port: First port in the scan range (inclusive).
        end_port: Last port in the scan range (inclusive).
        threads: Maximum number of concurrent scanning threads.
        timeout: Per-port connection timeout in seconds.
        grab_banners: Whether to attempt banner grabbing on open ports.
        on_result: Callback invoked for each completed port scan.
                   Receives (result, completed_count, total_count).
        show_all: If True, report all ports. If False, only open/filtered.

    Returns:
        A completed ScanReport with all results.

    Raises:
        socket.gaierror: If the target hostname cannot be resolved.
        ValueError: If port range is invalid.
    """
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        raise ValueError(
            f"Invalid port range: {start_port}-{end_port}. "
            f"Must be between 1 and 65535 with start <= end."
        )

    resolved_ip = resolve_target(target)
    ports = range(start_port, end_port + 1)
    total = len(ports)

    report = ScanReport(
        target=target,
        resolved_ip=resolved_ip,
        port_range=(start_port, end_port),
        start_time=datetime.now(),
        threads=threads,
    )

    completed = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all port scan tasks
        future_to_port = {
            executor.submit(scan_port, resolved_ip, port, timeout, grab_banners): port
            for port in ports
        }

        # Collect results as they complete
        for future in as_completed(future_to_port):
            result = future.result()
            completed += 1

            # Always store open and filtered; store closed only if show_all
            if result.status in (PortStatus.OPEN, PortStatus.FILTERED) or show_all:
                report.results.append(result)

            if on_result is not None:
                on_result(result, completed, total)

    report.end_time = datetime.now()

    # Sort results by port number for clean output
    report.results.sort(key=lambda r: r.port)

    return report
