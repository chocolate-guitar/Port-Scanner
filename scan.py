#!/usr/bin/env python3
"""
PortScanner — Multi-Threaded TCP Port Scanner

A robust, clean command-line tool for scanning TCP ports on target hosts.
Uses Python's standard library exclusively (no external dependencies).

Usage:
    python scan.py <target> [options]

Examples:
    python scan.py 127.0.0.1
    python scan.py 127.0.0.1 -p 1-1024 -t 300
    python scan.py 127.0.0.1 -p 80,443,8080
    python scan.py 127.0.0.1 -p web --banner
"""

import argparse
import socket
import sys

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
from portscanner.targets import parse_ports


def _validate_threads(value: str) -> int:
    """Validate that --threads is a positive integer.

    Args:
        value: The raw string value from argparse.

    Returns:
        The validated integer thread count.

    Raises:
        argparse.ArgumentTypeError: If the value is not a positive integer.
    """
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--threads must be an integer, got: '{value}'."
        )
    if n < 1:
        raise argparse.ArgumentTypeError(
            f"--threads must be >= 1, got: {n}."
        )
    return n


def _validate_timeout(value: str) -> float:
    """Validate that --timeout is a positive float.

    Args:
        value: The raw string value from argparse.

    Returns:
        The validated float timeout.

    Raises:
        argparse.ArgumentTypeError: If the value is not a positive number.
    """
    try:
        t = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--timeout must be a number, got: '{value}'."
        )
    if t <= 0:
        raise argparse.ArgumentTypeError(
            f"--timeout must be > 0, got: {t}."
        )
    return t


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
            f"  python scan.py 127.0.0.1\n"
            f"  python scan.py 127.0.0.1 -p 1-1024 -t 300\n"
            f"  python scan.py 127.0.0.1 -p 80,443,8080 --banner\n"
            f"  python scan.py 127.0.0.1 -p all --timeout 2.0{Colors.RESET}"
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
        type=parse_ports,
        default="common",
        metavar="SPEC",
        help=(
            "Port spec to scan. Formats: 80 | 1-1024 | 80,443 | 1-100,443,8080-8090 | "
            "common | all | web | top100 | high  (default: common = 1-1024)"
        ),
    )

    parser.add_argument(
        "-t", "--threads",
        type=_validate_threads,
        default=200,
        metavar="N",
        help="Number of concurrent threads, >= 1 (default: 200).",
    )

    parser.add_argument(
        "--timeout",
        type=_validate_timeout,
        default=1.5,
        metavar="SEC",
        help="Per-port connection timeout in seconds, > 0 (default: 1.5).",
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


def main() -> int:
    """Main entry point for the port scanner CLI.

    Returns:
        Exit code: 0 for success, 1 for errors, 130 for Ctrl+C.
    """
    parser = build_parser()
    args = parser.parse_args()

    # Print banner
    print_banner()

    # args.ports is already a list[int] — parse_ports() ran as the type converter.
    ports: list[int] = args.ports

    # Resolve hostname exactly once
    try:
        resolved_ip = resolve_target(args.target)
    except socket.gaierror:
        print_error(
            f"Cannot resolve hostname '{args.target}'.\n"
            f"         Please check the target address and your DNS configuration."
        )
        return 1

    # Cap threads to the number of ports (no point having more threads than ports)
    threads = min(args.threads, len(ports))

    # Display scan configuration
    print_scan_config(
        target=args.target,
        resolved_ip=resolved_ip,
        ports=ports,
        threads=threads,
        timeout=args.timeout,
        scan_type="TCP Connect",
    )

    # Ethical reminder for large scans
    if len(ports) > 10000:
        print_warning(
            "Scanning a large port range. Ensure you have authorization "
            "to scan this target.\n"
        )

    print_info("Scanning in progress...\n")

    # Define the real-time callback
    def on_result(result: PortResult, completed: int, total: int) -> None:
        print_progress(completed, total, result)

    # Run the scan — KeyboardInterrupt is handled inside run_scan
    try:
        report = run_scan(
            target=resolved_ip,
            ports=ports,
            threads=threads,
            timeout=args.timeout,
            grab_banners=args.banner,
            on_result=on_result,
            show_all=args.show_all,
        )
    except ValueError as e:
        print_error(str(e))
        return 1

    # Print results (partial or complete)
    print_results_summary(report)

    if report.interrupted:
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
