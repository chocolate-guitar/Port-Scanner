# 🔍 PortScanner — Multi-Threaded TCP Port Scanner

A robust, clean, and fast command-line port scanner built with Python's standard library. Zero external dependencies.

<p align="center">
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+">
<img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License">
<img src="https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square" alt="No Dependencies">
<img src="https://img.shields.io/badge/Platform-Cross--Platform-orange?style=flat-square" alt="Cross Platform">
</p>

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [How It Works](#-how-it-works)
- [TCP Connect vs SYN Scan](#-tcp-connect-scan-vs-syn-stealth-scan)
- [Ethical Considerations](#-ethical-considerations)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---|---|
| **Multi-Threaded** | Uses `concurrent.futures.ThreadPoolExecutor` for concurrent port scanning (default: 200 threads) |
| **Real-Time Output** | Live progress bar with per-port results displayed as they complete |
| **Banner Grabbing** | Optional service banner capture from open ports (SSH, FTP, SMTP, etc.) |
| **Service Detection** | Identifies 50+ well-known services by port number |
| **Flexible Port Specs** | Supports ranges (`1-1024`), lists (`80,443`), and presets (`common`, `all`, `web`) |
| **Zero Dependencies** | Built entirely on Python's standard library |
| **Clean CLI** | Colored output, ASCII art banner, progress bars, and formatted result tables |
| **Graceful Handling** | Proper Ctrl+C handling, DNS resolution errors, and timeout management |

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** (uses modern type hinting syntax)

### Installation

No installation required — just clone and run:

```bash
git clone https://github.com/yourusername/portscanner.git
cd portscanner
```

### Run Your First Scan

```bash
# Scan the well-known ports (1-1024) on a target
python scan.py scanme.nmap.org

# Scan specific ports
python scan.py 192.168.1.1 -p 22,80,443,3306,8080

# Full port scan with banner grabbing
python scan.py 10.0.0.1 -p all --banner -t 500
```

---

## 📖 Usage

```
usage: portscanner [-h] [-p RANGE] [-t N] [--timeout SEC] [--banner] [--show-all] [-v] target

positional arguments:
  target                Target IP address or hostname to scan

options:
  -h, --help            Show this help message and exit
  -p, --ports RANGE     Port range to scan (default: 1-1024)
  -t, --threads N       Number of concurrent threads (default: 200)
  --timeout SEC         Per-port connection timeout in seconds (default: 1.5)
  --banner              Attempt to grab service banners from open ports
  --show-all            Show all ports including closed
  -v, --version         Show program version
```

### Port Specification Formats

| Format | Example | Description |
|---|---|---|
| Single port | `-p 80` | Scan port 80 only |
| Range | `-p 1-1024` | Scan ports 1 through 1024 |
| List | `-p 22,80,443` | Scan specific ports (scans the full range between min and max) |
| Preset: `common` | `-p common` | Ports 1–1024 (well-known ports) |
| Preset: `all` | `-p all` | Ports 1–65535 (full range) |
| Preset: `web` | `-p web` | Ports 80–443 |
| Preset: `top100` | `-p top100` | Ports 1–100 |
| Preset: `high` | `-p high` | Ports 1024–65535 (ephemeral range) |

### Example Commands

```bash
# Quick scan of common web ports
python scan.py example.com -p web

# Full scan with high thread count and banner grabbing
python scan.py 192.168.1.1 -p all -t 500 --banner --timeout 2.0

# Scan with all results shown (including closed)
python scan.py 10.0.0.1 -p 1-100 --show-all

# Scan a single port
python scan.py 192.168.1.1 -p 22
```

---

## 🏗 Architecture

```
Port Scanner/
├── scan.py                  # Main CLI entry point
├── README.md                # This file
└── portscanner/             # Core package
    ├── __init__.py           # Package metadata
    ├── scanner.py            # Scanning engine (TCP Connect, threading)
    ├── models.py             # Data models (PortResult, ScanReport)
    └── display.py            # Terminal UI (colors, progress, tables)
```

### Module Responsibilities

| Module | Purpose |
|---|---|
| `scan.py` | CLI argument parsing, signal handling, orchestration |
| `scanner.py` | Socket-level port probing, banner grabbing, thread pool management |
| `models.py` | `PortResult` and `ScanReport` dataclasses with computed properties |
| `display.py` | ANSI-colored output, progress bars, result tables, error formatting |

---

## 🔬 How It Works

### TCP Connect Scan Flow

```
Scanner                          Target
  │                                │
  ├──── SYN ─────────────────────►│
  │                                │
  │◄──── SYN-ACK ─────────────────┤  → Port is OPEN
  │                                │
  ├──── ACK ─────────────────────►│  (Connection established)
  │                                │
  ├──── RST ─────────────────────►│  (Connection torn down)
  │                                │


  ├──── SYN ─────────────────────►│
  │                                │
  │◄──── RST ─────────────────────┤  → Port is CLOSED


  ├──── SYN ─────────────────────►│
  │                                │
  │         (no response)          │  → Port is FILTERED
  │         (timeout expires)      │
```

### Port States

| State | Meaning | Cause |
|---|---|---|
| **OPEN** | A service is listening and accepting connections | `connect()` succeeds |
| **CLOSED** | No service is listening, but the host is reachable | Connection refused (RST) |
| **FILTERED** | Cannot determine state — likely firewalled | Connection times out |

### Threading Model

The scanner uses `concurrent.futures.ThreadPoolExecutor` to distribute work:

1. **Task submission**: Each port is submitted as an independent scanning task.
2. **Concurrent execution**: Up to `N` threads (default: 200) run simultaneously.
3. **Result collection**: `as_completed()` yields results as soon as each thread finishes, enabling real-time progress display.
4. **Resource management**: The `with` statement ensures clean thread pool shutdown.

```python
with ThreadPoolExecutor(max_workers=threads) as executor:
    futures = {executor.submit(scan_port, ip, port): port for port in ports}
    for future in as_completed(futures):
        result = future.result()  # Process immediately
```

---

## ⚔️ TCP Connect Scan vs SYN Stealth Scan

### TCP Connect Scan (What This Tool Uses)

A **TCP Connect** scan performs a full three-way handshake (`SYN → SYN-ACK → ACK`) using the operating system's `connect()` system call.

| Aspect | Detail |
|---|---|
| **Mechanism** | Full TCP handshake via `socket.connect()` |
| **Privileges** | No special permissions needed — runs as a regular user |
| **Stealth** | ❌ **Not stealthy** — the connection is fully established and logged by the target |
| **Speed** | Slower — must complete the full handshake and then tear down the connection |
| **Reliability** | Very reliable — the OS handles TCP/IP stack nuances |
| **Detection** | Easily detected — shows up in server logs, IDS/IPS systems |
| **Dependencies** | Python standard library only (`socket` module) |

### SYN Stealth Scan (Not Implemented — Requires `scapy`)

A **SYN scan** sends only the initial `SYN` packet and analyzes the response without completing the handshake. It's called "half-open" because the connection is never fully established.

| Aspect | Detail |
|---|---|
| **Mechanism** | Send raw `SYN` packet, analyze `SYN-ACK` or `RST` response |
| **Privileges** | ⚠️ **Requires root/admin** — needs raw socket access |
| **Stealth** | ✅ **More stealthy** — no full connection, fewer logs generated |
| **Speed** | Faster — no handshake completion or teardown overhead |
| **Reliability** | Can be affected by firewalls and OS-level packet filtering |
| **Detection** | Harder to detect, but modern IDS systems can still flag SYN scans |
| **Dependencies** | Requires `scapy` library (`pip install scapy`) |

### Why SYN Scanning Requires `scapy`

Python's standard `socket` module operates at the **transport layer** and only supports established TCP connections. SYN scanning requires crafting **raw packets** at the network layer, which means:

1. **Raw socket access**: Creating sockets with `socket.SOCK_RAW` requires root privileges.
2. **Packet construction**: You need to manually build TCP headers with specific flags.
3. **Packet sniffing**: You must capture and parse raw responses at the IP level.

The `scapy` library provides all of this in a Pythonic interface:

```bash
pip install scapy
```

```python
from scapy.all import sr1, IP, TCP

# Send SYN, receive SYN-ACK or RST
response = sr1(IP(dst="target")/TCP(dport=80, flags="S"), timeout=2)
if response and response.haslayer(TCP):
    if response[TCP].flags == 0x12:  # SYN-ACK
        print("Port 80 is OPEN")
    elif response[TCP].flags == 0x14:  # RST
        print("Port 80 is CLOSED")
```

> **Note**: SYN scanning is intentionally not included in this tool to keep it dependency-free and usable without root privileges. For most legitimate network auditing purposes, a TCP Connect scan is sufficient.

---

## ⚖️ Ethical Considerations

### ⚠️ IMPORTANT: Legal and Ethical Use Only

Port scanning can be a legitimate and valuable tool for network administrators, security professionals, and penetration testers. However, **scanning networks without explicit authorization is illegal in many jurisdictions** and can have serious consequences.

### Rules of Engagement

1. **Always obtain written authorization** before scanning any network or host that you do not own.

2. **Scan only targets you are authorized to test.** This includes:
   - Your own machines and networks
   - Systems for which you have a signed penetration testing agreement
   - Intentionally vulnerable practice environments (e.g., `scanme.nmap.org`, HackTheBox, TryHackMe)

3. **Never scan production systems** without coordinating with the system owner and having a rollback plan.

4. **Be aware of local laws.** In many countries, unauthorized port scanning violates computer crime laws:
   - 🇺🇸 **USA**: Computer Fraud and Abuse Act (CFAA)
   - 🇬🇧 **UK**: Computer Misuse Act 1990
   - 🇪🇺 **EU**: Directive on Attacks Against Information Systems
   - 🇮🇳 **India**: Information Technology Act, 2000 (Sections 43, 66)

5. **Document everything.** Maintain records of:
   - Scope of authorized scanning
   - Date and time of scans
   - Targets scanned
   - Results obtained

### Safe Practice Environments

| Resource | Description |
|---|---|
| `scanme.nmap.org` | Nmap's official test target — authorized for scanning |
| [HackTheBox](https://www.hackthebox.eu) | Penetration testing labs |
| [TryHackMe](https://tryhackme.com) | Guided cybersecurity challenges |
| [VulnHub](https://www.vulnhub.com) | Downloadable vulnerable VMs |
| Your own lab | Set up VMs on your local network |

### Responsible Disclosure

If you discover vulnerabilities during authorized scanning:
- **Do not exploit** them beyond what is needed to verify the finding.
- **Report** findings to the system owner through proper channels.
- **Follow** your organization's vulnerability disclosure policy.

---

## 📄 License

This project is provided for **educational and authorized security testing purposes only**. Use responsibly.

```
MIT License

Copyright (c) 2024 PortScanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
