"""
Terminal display and formatting utilities.

Provides colored, structured CLI output for scan progress and results.
Uses ANSI escape codes directly — no external dependencies required.
"""

import shutil
import sys
from datetime import datetime
from typing import TextIO

from .models import PortResult, PortStatus, ScanReport


# ── ANSI Color Codes ──────────────────────────────────────────────────────────

class Colors:
    """ANSI escape sequences for terminal styling."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    # Foreground colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GREY = "\033[90m"

    # Bright foreground
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


def _supports_color(stream: TextIO = sys.stdout) -> bool:
    """Check if the terminal supports ANSI color codes."""
    if not hasattr(stream, "isatty"):
        return False
    return stream.isatty()


# Disable colors if terminal doesn't support them
if not _supports_color():
    for attr in dir(Colors):
        if not attr.startswith("_"):
            setattr(Colors, attr, "")


def _get_terminal_width() -> int:
    """Get current terminal width, defaulting to 80."""
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def _hr(char: str = "─", width: int | None = None) -> str:
    """Create a horizontal rule string."""
    w = width or min(_get_terminal_width(), 90)
    return char * w


def _status_color(status: PortStatus) -> str:
    """Return the ANSI color code for a given port status."""
    return {
        PortStatus.OPEN: Colors.BRIGHT_GREEN,
        PortStatus.CLOSED: Colors.GREY,
        PortStatus.FILTERED: Colors.BRIGHT_YELLOW,
    }.get(status, Colors.RESET)


def _status_icon(status: PortStatus) -> str:
    """Return a unicode icon for a given port status."""
    return {
        PortStatus.OPEN: "●",
        PortStatus.CLOSED: "○",
        PortStatus.FILTERED: "◐",
    }.get(status, "?")


# ── Display Functions ─────────────────────────────────────────────────────────

def print_banner() -> None:
    """Print the application banner/header."""
    banner = f"""
{Colors.BRIGHT_CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        ██████╗  ██████╗ ██████╗ ████████╗                 ║
    ║        ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝                ║
    ║        ██████╔╝██║   ██║██████╔╝   ██║                   ║
    ║        ██╔═══╝ ██║   ██║██╔══██╗   ██║                   ║
    ║        ██║     ╚██████╔╝██║  ██║   ██║                   ║
    ║        ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                   ║
    ║                                                           ║
    ║    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗  ║
    ║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝  ║
    ║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗    ║
    ║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝    ║
    ║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗  ║
    ║    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝  ║
    ║                                                           ║
    ║         {Colors.BRIGHT_WHITE}Multi-Threaded TCP Port Scanner v1.0{Colors.BRIGHT_CYAN}            ║
    ║         {Colors.DIM}{Colors.CYAN}github.com/portscanner{Colors.RESET}{Colors.BRIGHT_CYAN}{Colors.BOLD}                          ║
    ╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def print_scan_config(
    target: str,
    resolved_ip: str,
    port_range: tuple[int, int],
    threads: int,
    timeout: float,
    scan_type: str = "TCP Connect",
) -> None:
    """Print the scan configuration summary before scanning begins."""
    width = min(_get_terminal_width(), 90)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"  {Colors.BRIGHT_CYAN}{Colors.BOLD}┌{'─' * (width - 4)}┐{Colors.RESET}")
    print(f"  {Colors.BRIGHT_CYAN}{Colors.BOLD}│{Colors.RESET}  {Colors.BOLD}SCAN CONFIGURATION{' ' * (width - 24)}{Colors.BRIGHT_CYAN}{Colors.BOLD}│{Colors.RESET}")
    print(f"  {Colors.BRIGHT_CYAN}{Colors.BOLD}├{'─' * (width - 4)}┤{Colors.RESET}")

    rows = [
        ("Target", f"{target} → {Colors.BRIGHT_WHITE}{resolved_ip}{Colors.RESET}"),
        ("Port Range", f"{Colors.BRIGHT_WHITE}{port_range[0]}{Colors.RESET} – {Colors.BRIGHT_WHITE}{port_range[1]}{Colors.RESET}  ({port_range[1] - port_range[0] + 1:,} ports)"),
        ("Scan Type", f"{Colors.BRIGHT_MAGENTA}{scan_type}{Colors.RESET}"),
        ("Threads", f"{Colors.BRIGHT_WHITE}{threads}{Colors.RESET}"),
        ("Timeout", f"{Colors.BRIGHT_WHITE}{timeout}s{Colors.RESET}"),
        ("Started", f"{Colors.DIM}{now}{Colors.RESET}"),
    ]

    for label, value in rows:
        print(f"  {Colors.BRIGHT_CYAN}{Colors.BOLD}│{Colors.RESET}   {Colors.CYAN}{label:12s}{Colors.RESET} {value}")

    print(f"  {Colors.BRIGHT_CYAN}{Colors.BOLD}└{'─' * (width - 4)}┘{Colors.RESET}")
    print()


def print_progress(completed: int, total: int, result: PortResult) -> None:
    """Print a real-time progress update for a single port result.

    Only prints open and filtered ports to avoid flooding the terminal
    with thousands of closed port lines.
    """
    pct = (completed / total) * 100
    bar_width = 30
    filled = int(bar_width * completed / total)
    bar = f"{'█' * filled}{'░' * (bar_width - filled)}"

    # Always update the progress bar on the same line
    progress_line = (
        f"\r  {Colors.DIM}[{Colors.BRIGHT_CYAN}{bar}{Colors.DIM}]{Colors.RESET} "
        f"{Colors.BRIGHT_WHITE}{pct:5.1f}%{Colors.RESET} "
        f"{Colors.DIM}({completed:,}/{total:,}){Colors.RESET}"
    )

    if result.status == PortStatus.OPEN:
        # Clear progress line, print the open port, then re-print progress
        sys.stdout.write(f"\r{' ' * (_get_terminal_width() - 1)}\r")
        sys.stdout.flush()

        color = _status_color(result.status)
        icon = _status_icon(result.status)
        service_str = f" {Colors.DIM}({result.service}){Colors.RESET}" if result.service else ""
        banner_str = f"  {Colors.DIM}│ {result.banner}{Colors.RESET}" if result.banner else ""
        latency = f"  {Colors.DIM}{result.response_time_ms:.1f}ms{Colors.RESET}" if result.response_time_ms else ""

        print(
            f"  {color}{icon} {Colors.BOLD}Port {result.port:<6d}{Colors.RESET} "
            f"{color}{result.status.value.upper():8s}{Colors.RESET}"
            f"{service_str}{latency}{banner_str}"
        )

    elif result.status == PortStatus.FILTERED:
        sys.stdout.write(f"\r{' ' * (_get_terminal_width() - 1)}\r")
        sys.stdout.flush()

        color = _status_color(result.status)
        icon = _status_icon(result.status)
        service_str = f" {Colors.DIM}({result.service}){Colors.RESET}" if result.service else ""

        print(
            f"  {color}{icon} {Colors.BOLD}Port {result.port:<6d}{Colors.RESET} "
            f"{color}{result.status.value.upper():8s}{Colors.RESET}"
            f"{service_str}"
        )

    # Re-print progress bar
    sys.stdout.write(progress_line)
    sys.stdout.flush()


def print_results_summary(report: ScanReport) -> None:
    """Print the final scan results summary table."""
    width = min(_get_terminal_width(), 90)

    # Clear the progress line
    sys.stdout.write(f"\r{' ' * (_get_terminal_width() - 1)}\r")
    sys.stdout.flush()

    print()
    print(f"  {Colors.BRIGHT_CYAN}{Colors.BOLD}{'═' * (width - 4)}{Colors.RESET}")
    print(f"  {Colors.BOLD}{Colors.BRIGHT_WHITE}  SCAN RESULTS SUMMARY{Colors.RESET}")
    print(f"  {Colors.BRIGHT_CYAN}{Colors.BOLD}{'═' * (width - 4)}{Colors.RESET}")
    print()

    # Summary statistics
    open_count = len(report.open_ports)
    closed_count = len(report.closed_ports)
    filtered_count = len(report.filtered_ports)
    total_scanned = report.total_ports

    print(f"  {Colors.BOLD}Statistics:{Colors.RESET}")
    print(f"    {Colors.BRIGHT_GREEN}● Open:     {open_count:>6,}{Colors.RESET}")
    print(f"    {Colors.GREY}○ Closed:   {total_scanned - open_count - filtered_count:>6,}{Colors.RESET}")
    print(f"    {Colors.BRIGHT_YELLOW}◐ Filtered: {filtered_count:>6,}{Colors.RESET}")
    print(f"    {Colors.BRIGHT_WHITE}  Total:    {total_scanned:>6,}{Colors.RESET}")
    print()

    # Open ports table
    if report.open_ports:
        print(f"  {Colors.BRIGHT_GREEN}{Colors.BOLD}  Open Ports Detail:{Colors.RESET}")
        print(f"  {Colors.DIM}  {'─' * (width - 8)}{Colors.RESET}")
        print(
            f"  {Colors.BOLD}  {'PORT':<10s} {'STATE':<12s} {'SERVICE':<20s} "
            f"{'LATENCY':<12s} {'BANNER'}{Colors.RESET}"
        )
        print(f"  {Colors.DIM}  {'─' * (width - 8)}{Colors.RESET}")

        for r in report.open_ports:
            color = _status_color(r.status)
            svc = r.service or "unknown"
            latency = f"{r.response_time_ms:.1f}ms" if r.response_time_ms else "—"
            banner = r.banner[:40] + "…" if len(r.banner) > 40 else r.banner

            print(
                f"  {color}  {r.port:<10d} {r.status.value.upper():<12s} "
                f"{svc:<20s} {latency:<12s} {Colors.DIM}{banner}{Colors.RESET}"
            )

        print(f"  {Colors.DIM}  {'─' * (width - 8)}{Colors.RESET}")
    else:
        print(f"  {Colors.BRIGHT_YELLOW}  ⚠  No open ports found in the scanned range.{Colors.RESET}")

    # Filtered ports (if any)
    if report.filtered_ports:
        print()
        print(f"  {Colors.BRIGHT_YELLOW}{Colors.BOLD}  Filtered Ports:{Colors.RESET}", end="  ")
        filtered_list = [str(r.port) for r in report.filtered_ports[:20]]
        print(f"{Colors.BRIGHT_YELLOW}{', '.join(filtered_list)}{Colors.RESET}", end="")
        if len(report.filtered_ports) > 20:
            print(f" {Colors.DIM}… and {len(report.filtered_ports) - 20} more{Colors.RESET}", end="")
        print()

    print()

    # Timing
    duration = report.duration_seconds
    rate = report.total_ports / duration if duration > 0 else 0
    print(f"  {Colors.DIM}  Scan completed in {duration:.2f}s ({rate:,.0f} ports/sec){Colors.RESET}")
    if report.end_time:
        print(f"  {Colors.DIM}  Finished at {report.end_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print()
    print(f"  {Colors.BRIGHT_CYAN}{'═' * (width - 4)}{Colors.RESET}")
    print()


def print_error(message: str) -> None:
    """Print a formatted error message."""
    print(f"\n  {Colors.BRIGHT_RED}{Colors.BOLD}✖ ERROR:{Colors.RESET} {Colors.RED}{message}{Colors.RESET}\n")


def print_warning(message: str) -> None:
    """Print a formatted warning message."""
    print(f"  {Colors.BRIGHT_YELLOW}{Colors.BOLD}⚠ WARNING:{Colors.RESET} {Colors.YELLOW}{message}{Colors.RESET}")


def print_info(message: str) -> None:
    """Print a formatted info message."""
    print(f"  {Colors.BRIGHT_CYAN}ℹ{Colors.RESET} {message}")
