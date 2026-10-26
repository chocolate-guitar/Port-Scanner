"""
Target specification parsing and expansion.

Handles port specification strings (ranges, lists, named presets) and
(in Phase 3) CIDR/multi-host target expansion.
"""

import argparse

# ── Top-100 commonly targeted ports (real-world list, not 1-100) ──────────────
# Assembled from Nmap's top-ports data and common pentest targets.
_TOP100_PORTS: list[int] = sorted(set([
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 514, 515, 587, 631, 636,
    993, 995, 1080, 1433, 1434, 1521, 1723, 2049,
    2082, 2083, 2379, 2380, 3000, 3306, 3389, 4369,
    4444, 4848, 5432, 5671, 5672, 5900, 5985, 5986,
    6379, 6443, 6667, 7001, 7002, 8000, 8008, 8009,
    8069, 8080, 8161, 8443, 8888, 9000, 9001, 9042,
    9090, 9092, 9160, 9200, 9300, 10000, 10250, 10251,
    10252, 10443, 11000, 11211, 15671, 15672, 16379,
    20, 25672, 27017, 27018, 27019, 28017, 30000,
    32768, 49152, 49153, 49154, 50070, 61616, 67,
    68, 69, 119, 123, 137, 138, 161, 162, 500,
    502, 554, 623,
]))

# Pad / trim to exactly 100 unique ports
assert len(_TOP100_PORTS) == 100, (
    f"_TOP100_PORTS must have exactly 100 entries, has {len(_TOP100_PORTS)}"
)

# ── Named presets ─────────────────────────────────────────────────────────────
_PRESETS: dict[str, list[int]] = {
    "common": list(range(1, 1025)),          # 1-1024  (well-known ports)
    "all":    list(range(1, 65536)),         # 1-65535 (full range)
    "web":    [80, 443, 8000, 8080, 8443, 8888],
    "top100": _TOP100_PORTS,
    "high":   list(range(1024, 65536)),      # 1024-65535
}


def parse_ports(spec: str) -> list[int]:
    """Parse a port specification string into a sorted, deduplicated list of ports.

    Supported formats (and combinations via comma-separation):
        - Single port:       ``"80"``          → ``[80]``
        - Range:             ``"1-1024"``       → ``[1, 2, …, 1024]``
        - Comma list:        ``"22,80,443"``    → ``[22, 80, 443]``
        - Mixed:             ``"1-100,443,8080-8090"``
        - Named preset:      ``"common"`` | ``"all"`` | ``"web"`` | ``"top100"`` | ``"high"``

    Args:
        spec: The port specification string from the CLI ``--ports`` argument.

    Returns:
        A sorted list of unique port integers.

    Raises:
        argparse.ArgumentTypeError: If any port is out of range or the spec
            cannot be parsed.
    """
    lowered = spec.strip().lower()

    # Named preset — must be the entire spec (no mixing presets with ranges)
    if lowered in _PRESETS:
        return _PRESETS[lowered]

    ports: set[int] = set()

    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            # Could be a range like "1-1024"
            parts = token.split("-", 1)
            try:
                start, end = int(parts[0].strip()), int(parts[1].strip())
            except ValueError:
                raise argparse.ArgumentTypeError(
                    f"Invalid port range: '{token}'. Expected format: START-END (e.g. 1-1024)."
                )
            if start < 1 or start > 65535:
                raise argparse.ArgumentTypeError(
                    f"Port {start} is out of range. Ports must be between 1 and 65535."
                )
            if end < 1 or end > 65535:
                raise argparse.ArgumentTypeError(
                    f"Port {end} is out of range. Ports must be between 1 and 65535."
                )
            if start > end:
                raise argparse.ArgumentTypeError(
                    f"Invalid range '{token}': start port ({start}) must be ≤ end port ({end})."
                )
            ports.update(range(start, end + 1))
        else:
            # Single port
            try:
                p = int(token)
            except ValueError:
                raise argparse.ArgumentTypeError(
                    f"Invalid port: '{token}'. Expected an integer or a range like 1-1024.\n"
                    f"  Accepted formats: 80 | 1-1024 | 80,443 | common | all | web | top100 | high"
                )
            if p < 1 or p > 65535:
                raise argparse.ArgumentTypeError(
                    f"Port {p} is out of range. Ports must be between 1 and 65535."
                )
            ports.add(p)

    if not ports:
        raise argparse.ArgumentTypeError(
            f"Empty port specification: '{spec}'. "
            f"Use formats like: 80 | 1-1024 | 80,443 | common | all | web | top100 | high"
        )

    return sorted(ports)
