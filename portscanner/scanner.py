"""
Core scanning engine.

Implements TCP Connect scanning with multi-threaded execution using
concurrent.futures.ThreadPoolExecutor. Each port is probed independently,
and results are reported in real-time via a callback mechanism.
"""

import errno
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Optional

from .models import PortResult, PortStatus, ScanReport

# ── errno sets for status classification ─────────────────────────────────────
# Build these once at import time so we never crash on platforms that lack
# certain constants (Windows uses WSAE* codes; Linux/macOS use POSIX codes).

def _errno_set(*names: str, fallbacks: tuple[int, ...] = ()) -> frozenset[int]:
    """Collect errno values by name, ignoring names absent on this platform."""
    values: set[int] = set(fallbacks)
    for name in names:
        v = getattr(errno, name, None)
        if v is not None:
            values.add(v)
    return frozenset(values)


# connect_ex returns 0 on success; anything else is an error code.
_REFUSED_ERRNOS: frozenset[int] = _errno_set(
    "ECONNREFUSED",
    # Windows: WSAECONNREFUSED = 10061
    fallbacks=(10061,),
)

_FILTERED_ERRNOS: frozenset[int] = _errno_set(
    "ETIMEDOUT",    # macOS: 60  Linux: 110  — also returned by connect_ex on timeout
    "EAGAIN",       # macOS returns 35 (EAGAIN/EWOULDBLOCK) for connect_ex timeouts
    "EWOULDBLOCK",  # same value as EAGAIN on most POSIX systems
    "EHOSTUNREACH",
    "ENETUNREACH",
    "EHOSTDOWN",
    # Windows equivalents
    fallbacks=(
        10060,  # WSAETIMEDOUT
        10065,  # WSAEHOSTUNREACH
        10051,  # WSAENETUNREACH
        10064,  # WSAEHOSTDOWN
    ),
)

_RESOURCE_ERRNOS: frozenset[int] = _errno_set(
    "EMFILE",   # too many open file descriptors (process limit)
    "ENFILE",   # too many open files (system limit)
)

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


def _do_connect(target_ip: str, port: int, timeout: float) -> tuple[int, Optional[socket.socket]]:
    """Open a TCP socket and attempt a connection.

    Returns the connect_ex result code and the open socket on success,
    or a non-zero code and None on any other outcome.
    The caller is responsible for closing the socket.

    Args:
        target_ip: The resolved IP address to connect to.
        port: The port number to probe.
        timeout: Connection timeout in seconds.

    Returns:
        A tuple of (result_code, socket_or_None).

    Raises:
        OSError: For resource-limit errors (EMFILE/ENFILE) so the caller
            can catch them separately.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        rc = sock.connect_ex((target_ip, port))
        if rc == 0:
            return rc, sock
        sock.close()
        return rc, None
    except OSError:
        sock.close()
        raise


def scan_port(
    target_ip: str,
    port: int,
    timeout: float = 1.5,
    grab_banners: bool = False,
) -> PortResult:
    """Scan a single port using TCP Connect method.

    Maps connect_ex return codes to port statuses explicitly:

    * ``0``                           → :attr:`~PortStatus.OPEN`
    * ``ECONNREFUSED`` (61 / 10061)   → :attr:`~PortStatus.CLOSED`
    * ``EAGAIN / ETIMEDOUT / ...``    → :attr:`~PortStatus.FILTERED`
    * ``EMFILE / ENFILE``             → retry once; if still failing
                                         → :attr:`~PortStatus.ERROR`

    This avoids the bug where ``connect_ex`` returns a non-zero errno for
    a *timeout* (e.g. ``EAGAIN=35`` on macOS) and the old code mapped all
    non-zero codes to CLOSED.  The ``except socket.timeout`` branch never
    fires when using ``connect_ex``; it only fires with ``connect()``.

    Args:
        target_ip: The resolved IP address to scan.
        port: The port number to probe.
        timeout: Connection timeout in seconds.
        grab_banners: Whether to attempt banner grabbing on open ports.

    Returns:
        A :class:`PortResult` with the determined status and metadata.
    """
    service = get_service_name(port)
    start = time.perf_counter()

    def _attempt() -> PortResult:
        """Single connection attempt; raises OSError on resource exhaustion."""
        rc, sock = _do_connect(target_ip, port, timeout)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        if rc == 0:
            # Port is OPEN — optionally grab banner
            banner = ""
            if grab_banners and sock is not None:
                banner = grab_banner(sock)
            if sock is not None:
                sock.close()
            return PortResult(
                port=port,
                status=PortStatus.OPEN,
                service=service,
                banner=banner,
                response_time_ms=elapsed_ms,
            )

        if rc in _REFUSED_ERRNOS:
            return PortResult(
                port=port,
                status=PortStatus.CLOSED,
                service=service,
                response_time_ms=elapsed_ms,
            )

        if rc in _FILTERED_ERRNOS:
            return PortResult(
                port=port,
                status=PortStatus.FILTERED,
                service=service,
                response_time_ms=elapsed_ms,
            )

        # Unknown non-zero code — treat as filtered (firewalled / OS-specific)
        return PortResult(
            port=port,
            status=PortStatus.FILTERED,
            service=service,
            response_time_ms=elapsed_ms,
        )

    try:
        return _attempt()
    except OSError as exc:
        if exc.errno in _RESOURCE_ERRNOS:
            # Too many open files — give the OS a moment and retry once.
            time.sleep(0.1)
            try:
                return _attempt()
            except OSError as exc2:
                if exc2.errno in _RESOURCE_ERRNOS:
                    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                    return PortResult(
                        port=port,
                        status=PortStatus.ERROR,
                        service=service,
                        response_time_ms=elapsed_ms,
                    )
                # Second attempt failed for a different reason — treat as filtered
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                return PortResult(
                    port=port,
                    status=PortStatus.FILTERED,
                    service=service,
                    response_time_ms=elapsed_ms,
                )
        # Non-resource OSError (e.g. network unreachable at socket level)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return PortResult(
            port=port,
            status=PortStatus.FILTERED,
            service=service,
            response_time_ms=elapsed_ms,
        )


def run_scan(
    target: str,
    ports: list[int],
    threads: int = 200,
    timeout: float = 1.5,
    grab_banners: bool = False,
    on_result: Optional[Callable[[PortResult, int, int], None]] = None,
    show_all: bool = False,
) -> ScanReport:
    """Execute a full port scan across the given list of ports.

    Distributes port scanning work across a thread pool for concurrent
    execution. Results are reported in real-time via the *on_result* callback.

    The *target* parameter must already be a resolved IP address (the caller
    is responsible for DNS resolution so it happens exactly once).

    On :exc:`KeyboardInterrupt`, the executor is shut down immediately
    (``cancel_futures=True``) and a partial :class:`ScanReport` is returned
    with ``interrupted=True``.

    Args:
        target: The already-resolved IP address to scan.
        ports: Sorted list of port numbers to probe.
        threads: Maximum number of concurrent scanning threads.
        timeout: Per-port connection timeout in seconds.
        grab_banners: Whether to attempt banner grabbing on open ports.
        on_result: Callback invoked for each completed port scan.
                   Receives ``(result, completed_count, total_count)``.
        show_all: If True, store all port results. If False, only
                  open, filtered, and error results are stored.

    Returns:
        A :class:`ScanReport` (possibly partial if interrupted).
    """
    total = len(ports)

    report = ScanReport(
        target=target,
        resolved_ip=target,
        ports=ports,
        start_time=datetime.now(),
        threads=threads,
    )

    completed = 0
    executor = ThreadPoolExecutor(max_workers=threads)
    try:
        future_to_port = {
            executor.submit(scan_port, target, port, timeout, grab_banners): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            result = future.result()
            completed += 1

            # Always keep OPEN, FILTERED, ERROR; CLOSED only when show_all
            if result.status in (PortStatus.OPEN, PortStatus.FILTERED, PortStatus.ERROR) or show_all:
                report.results.append(result)

            if on_result is not None:
                on_result(result, completed, total)

    except KeyboardInterrupt:
        # Shut down immediately — don't wait for queued futures
        executor.shutdown(wait=False, cancel_futures=True)
        report.interrupted = True
        report.end_time = datetime.now()
        report.results.sort(key=lambda r: r.port)
        return report
    else:
        executor.shutdown(wait=False)

    report.end_time = datetime.now()

    # Sort results by port number for clean output
    report.results.sort(key=lambda r: r.port)

    # Warn about resource errors so the user knows to lower --threads
    error_count = len(report.error_ports)
    if error_count:
        print(
            f"\n  ⚠ WARNING: {error_count} port(s) returned ERROR (EMFILE/ENFILE — "
            f"too many open files). Consider a lower --threads value or raising "
            f"your ulimit (e.g. `ulimit -n 4096`).",
            file=sys.stderr,
        )

    return report
