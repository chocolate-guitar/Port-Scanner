#!/usr/bin/env python3
"""
PortScanner — Multi-Threaded TCP Port Scanner

A robust, clean command-line tool for scanning TCP ports on target hosts.
Uses Python's standard library exclusively (no external dependencies).

Usage:
    python scan.py <target> [options]

Examples:
    python scan.py 192.168.1.1
    python scan.py scanme.nmap.org -p 1-1024 -t 300
    python scan.py example.com -p 80,443,8080
    python scan.py 10.0.0.1 -p 1-65535 --timeout 2.0 --banner
"""

import argparse
import signal
import socket
import sys
from typing import NoReturn

from portscanner import __version__
from portscanner.display import (
    Colors,
    print_banner,
    print_error,
    print_info,
    print_progress,
    print_results_summary,
    print_scan_config,
    print_warning,
)
from portscanner.models import PortResult
from portscanner.scanner import resolve_target, run_scan


def parse_port_range(port_string: str) -> tuple[int, int]:
    """Parse a port range specification string.

    Supports formats:
        - Single port:   "80"       → (80, 80)
        - Range:         "1-1024"   → (1, 1024)
        - Comma list:    "80,443"   → handled by returning min/max
        - Named ranges:  "common"   → predefined ranges

    Args:
        port_string: The port specification string from CLI.

    Returns:
        A tuple of (start_port, end_port).

    Raises:
        argparse.ArgumentTypeError: If the port spec is invalid.
    """
    # Named presets
    presets = {
        "common": (1, 1024),
        "all": (1, 65535),
        "web": (80, 443),
        "top100": (1, 100),
        "high": (1024, 65535),
    }

    lowered = port_string.strip().lower()
    if lowered in presets:
        return presets[lowered]

    # Comma-separated list (e.g., "80,443,8080")
    if "," in port_string:
        try:
            ports = [int(p.strip()) for p in port_string.split(",")]
            for p in ports:
                if p < 1 or p > 65535:
                    raise argparse.ArgumentTypeError(
                        f"Port {p} is out of range (1-65535)."
                    )
            return (min(ports), max(ports))
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Invalid port list: '{port_string}'. Use comma-separated integers."
            )

    # Range (e.g., "1-1024")
    if "-" in port_string:
        parts = port_string.split("-", 1)
        try:
            start, end = int(parts[0].strip()), int(parts[1].strip())
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Invalid port range: '{port_string}'. Use format: START-END"
            )
        if start < 1 or end > 65535:
            raise argparse.ArgumentTypeError(
                f"Port numbers must be between 1 and 65535, got {start}-{end}."
            )
        if start > end:
            raise argparse.ArgumentTypeError(
                f"Start port ({start}) cannot be greater than end port ({end})."
            )
        return (start, end)

    # Single port
    try:
        port = int(port_string.strip())
        if port < 1 or port > 65535:
            raise argparse.ArgumentTypeError(
                f"Port {port} is out of range (1-65535)."
            )
        return (port, port)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid port specification: '{port_string}'.\n"
            f"  Accepted formats: 80 | 1-1024 | 80,443,8080 | common | all"
        )


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description=(
            f"{Colors.BRIGHT_CYAN}PortScanner{Colors.RESET} — "
            f"A multi-threaded TCP port scanning tool."
        ),
        epilog=(
            f"{Colors.DIM}Examples:\n"
            f"  python scan.py scanme.nmap.org\n"
            f"  python scan.py 192.168.1.1 -p 1-1024 -t 300\n"
            f"  python scan.py example.com -p 80,443,8080 --banner\n"
            f"  python scan.py 10.0.0.1 -p all --timeout 2.0{Colors.RESET}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target",
        type=str,
        help="Target IP address or hostname to scan.",
    )

    parser.add_argument(
        "-p", "--ports",
        type=str,
        default="1-1024",
        metavar="RANGE",
        help=(
            "Port range to scan. Formats: 80 | 1-1024 | 80,443 | "
            "common | all | web | top100 | high  (default: 1-1024)"
        ),
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=200,
        metavar="N",
        help="Number of concurrent threads (default: 200).",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        metavar="SEC",
        help="Per-port connection timeout in seconds (default: 1.5).",
    )

    parser.add_argument(
        "--banner",
        action="store_true",
        default=False,
        help="Attempt to grab service banners from open ports.",
    )

    parser.add_argument(
        "--show-all",
        action="store_true",
        default=False,
        help="Show all ports including closed (default: open/filtered only).",
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def handle_sigint(signum: int, frame: object) -> NoReturn:
    """Handle Ctrl+C gracefully."""
    print(f"\n\n  {Colors.BRIGHT_YELLOW}⚠  Scan interrupted by user (Ctrl+C).{Colors.RESET}\n")
    sys.exit(130)


def main() -> int:
    """Main entry point for the port scanner CLI.

    Returns:
        Exit code: 0 for success, 1 for errors.
    """
    # Register signal handler for clean Ctrl+C
    signal.signal(signal.SIGINT, handle_sigint)

    parser = build_parser()
    args = parser.parse_args()

    # Print banner
    print_banner()

    # Parse port range
    try:
        start_port, end_port = parse_port_range(args.ports)
    except argparse.ArgumentTypeError as e:
        print_error(str(e))
        return 1

    # Resolve hostname
    try:
        resolved_ip = resolve_target(args.target)
    except socket.gaierror:
        print_error(
            f"Cannot resolve hostname '{args.target}'.\n"
            f"         Please check the target address and your DNS configuration."
        )
        return 1

    # Validate thread count
    total_ports = end_port - start_port + 1
    threads = min(args.threads, total_ports)  # No point having more threads than ports

    # Display scan configuration
    print_scan_config(
        target=args.target,
        resolved_ip=resolved_ip,
        port_range=(start_port, end_port),
        threads=threads,
        timeout=args.timeout,
        scan_type="TCP Connect",
    )

    # Ethical reminder for large scans
    if total_ports > 10000:
        print_warning(
            "Scanning a large port range. Ensure you have authorization "
            "to scan this target.\n"
        )

    print_info("Scanning in progress...\n")

    # Define the real-time callback
    def on_result(result: PortResult, completed: int, total: int) -> None:
        print_progress(completed, total, result)

    # Run the scan
    try:
        report = run_scan(
            target=args.target,
            start_port=start_port,
            end_port=end_port,
            threads=threads,
            timeout=args.timeout,
            grab_banners=args.banner,
            on_result=on_result,
            show_all=args.show_all,
        )
    except ValueError as e:
        print_error(str(e))
        return 1
    except socket.gaierror:
        print_error(f"Failed to resolve target '{args.target}'.")
        return 1
    except KeyboardInterrupt:
        handle_sigint(signal.SIGINT, None)

    # Print results
    print_results_summary(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
