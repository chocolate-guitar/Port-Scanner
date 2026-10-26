"""
Data models for port scan results.

Uses dataclasses for clean, type-safe representation of scan outcomes.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class PortStatus(Enum):
    """Enumeration of possible port states."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    ERROR = "error"


@dataclass
class PortResult:
    """Result of scanning a single port.

    Attributes:
        port: The port number that was scanned.
        status: The determined status of the port.
        service: The well-known service name associated with the port, if any.
        banner: Any banner text grabbed from an open port.
        response_time_ms: Round-trip time in milliseconds, if measurable.
    """

    port: int
    status: PortStatus
    service: str = ""
    banner: str = ""
    response_time_ms: Optional[float] = None


@dataclass
class ScanReport:
    """Aggregated report for an entire scan session.

    Attributes:
        target: The original target string (IP or hostname).
        resolved_ip: The resolved IPv4/IPv6 address.
        ports: The sorted list of port numbers that were scanned.
        start_time: When the scan began.
        end_time: When the scan finished (None if still running).
        results: List of individual port results.
        scan_type: The type of scan performed (e.g., 'TCP Connect').
        threads: Number of concurrent threads used.
        interrupted: True if the scan was cut short by KeyboardInterrupt.
    """

    target: str
    resolved_ip: str
    ports: list[int]
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    results: list[PortResult] = field(default_factory=list)
    scan_type: str = "TCP Connect"
    threads: int = 100
    interrupted: bool = False

    @property
    def open_ports(self) -> list[PortResult]:
        """Return only results with OPEN status."""
        return [r for r in self.results if r.status == PortStatus.OPEN]

    @property
    def closed_ports(self) -> list[PortResult]:
        """Return only results with CLOSED status."""
        return [r for r in self.results if r.status == PortStatus.CLOSED]

    @property
    def filtered_ports(self) -> list[PortResult]:
        """Return only results with FILTERED status."""
        return [r for r in self.results if r.status == PortStatus.FILTERED]

    @property
    def error_ports(self) -> list[PortResult]:
        """Return only results with ERROR status."""
        return [r for r in self.results if r.status == PortStatus.ERROR]

    @property
    def duration_seconds(self) -> float:
        """Total scan duration in seconds."""
        if self.end_time is None:
            return (datetime.now() - self.start_time).total_seconds()
        return (self.end_time - self.start_time).total_seconds()

    @property
    def total_ports(self) -> int:
        """Total number of ports in the scan list."""
        return len(self.ports)
