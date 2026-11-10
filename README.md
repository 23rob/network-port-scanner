# 🔍 Network Port Scanner

[![CI](https://github.com/23rob/network-port-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/23rob/network-port-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![codecov](https://codecov.io/github/23rob/network-port-scanner/graph/badge.svg?token=JV6FUUKLTX)](https://codecov.io/github/23rob/network-port-scanner)

An async, multi-host TCP port scanner built for **network reconnaissance**, **security auditing**, and **CLI/automation usage** — with a proper pip-installable package layout, a 93-test suite at 96% coverage, and CI that actually runs it.

> ⚠️ **Legal & Ethical Use Only**
> Only scan hosts and networks you **own** or have **explicit written authorization** to test. Unauthorized scanning may violate the Computer Fraud and Abuse Act (US) or equivalent laws elsewhere. This tool is for educational and authorized security-testing purposes only.

---
**Example scan output:**
<img width="1261" height="287" alt="Example scan output showing open ports, service names, and filtered port summary" src="https://github.com/user-attachments/assets/cadaf694-f11f-4f6c-8cc0-b8510b82ef8b" />

## 🚀 Features

- ⚡ **Async scanning engine** (`asyncio`, not threads) with a bounded worker pool
- 🌐 **Multi-host & CIDR support** — scan a single IP, a comma list, or an entire subnet (`192.168.1.0/24`) in one run
- 🎯 **Flexible port specs** — `80`, `22,80,443`, `1-1024`, or any combination
- 📋 **Built-in top-ports set** — 45+ common/well-known ports mapped to service names
- 📡 **Banner grabbing** — including a proper TLS handshake for HTTPS ports, so encrypted banners are actually readable
- 🔁 **Automatic retry on filtered results** — cuts down false "filtered" classifications from transient network jitter (optional, `--no-retry` to disable)
- 🚦 **Correct three-state classification** — open / closed / filtered, distinguished properly (see [Engineering Notes](#-engineering-notes) for why this matters more than it sounds)
- 🎨 **Colorized output** — auto-detected TTY, respects `--no-color` and the [`NO_COLOR`](https://no-color.org/) convention
- 🛡️ **Safety rails** — CIDR blocks are capped from accidentally expanding to millions of hosts, and large scans require confirmation (or `-y`/`--yes`)
- 💻 **Interactive mode** (no arguments) or full CLI for scripting
- 📦 **JSON export** for feeding results into other tools
- 🧪 **93 tests, 96% coverage**, CI-tested on Python 3.10–3.12
- 📦 **Zero runtime dependencies** — pure standard library (`asyncio`, `ssl`, `ipaddress`, `argparse`), which matters for a security tool's supply-chain surface

---

## 📥 Installation
### Option 1: Standalone executable (Windows, no Python required)

Download the latest `portscan.exe` from the [Releases page](https://github.com/23rob/network-port-scanner/releases) and run it directly — no installation needed.

### Option 2: From source (all platforms, requires Python 3.10+)
```bash
git clone https://github.com/23rob/network-port-scanner.git
cd network-port-scanner
pip install .
```

This installs a `portscan` command on your PATH. For development (editable install + test tooling):

```bash
pip install -e ".[dev]"
```

---

## ▶️ Usage

### Interactive mode

```bash
portscan
```

### Command-line mode

```bash
# Single host, a port range, with service banners
portscan -t 192.168.1.10 -p 1-1024 --banners

# An entire subnet, common ports only
portscan -t 192.168.1.0/28 --top-ports

# Multiple explicit targets, export to JSON
portscan -t 10.0.0.5,10.0.0.6 -p 22,80,443 -o results.json

# Tune concurrency and timeout for a slow or lossy network
portscan -t 192.168.1.10 -p 1-65535 --timeout 2 --concurrency 100
```

### Full option reference

```
-t, --target       Target(s): hostname, IP, comma list, and/or CIDR
                    (e.g. 192.168.1.0/28). Omit for interactive mode.
-p, --ports        Ports: '80', '22,80,443', '1-1024', or combinations.
    --top-ports    Explicitly scan the built-in common/well-known ports set.
    --timeout      Per-port connection timeout in seconds (default: 1.0)
    --concurrency  Max concurrent in-flight connections (default: 200)
    --banners      Attempt to grab service banners on open ports.
    --no-retry     Disable the single automatic retry on filtered results.
-o, --output       Export results as JSON to FILE.
-v, --verbose      Show filtered/non-responsive ports too.
-q, --quiet        Suppress the progress indicator and pre-scan summary.
    --no-color     Disable colored output.
-y, --yes          Skip the confirmation prompt for very large scans.
    --version      Show version and exit.
```

---

## 🧠 Port States

- ✅ **OPEN** — a service accepted the connection
- ❌ **CLOSED** — the host actively refused the connection (RST received, nothing listening)
- 🚧 **FILTERED** — no response at all within the timeout — usually a firewall silently dropping packets

---

## ⚙️ Engineering Notes

This section exists because building this honestly meant benchmarking claims instead of assuming them, and a couple of the results weren't what I expected going in. I'd rather show that process than hide it.

### A real correctness bug, found by testing against a real target

The original (v1) version of this scanner used `socket.connect_ex()` with a timeout to classify ports. The assumption was that a timed-out connection attempt would raise `socket.timeout`, which the code caught and correctly labeled `filtered`.

That assumption was wrong. Testing against [`scanme.nmap.org`](https://nmap.org/book/testing.html) — the public test target Nmap's own maintainers provide specifically for this purpose — showed `connect_ex()` doesn't raise `socket.timeout` when a connection is still pending at the timeout; it just returns an ambiguous `EAGAIN` errno as an ordinary return value. The v1 logic (`if code == 0: open else: closed`) couldn't tell that apart from an instant refusal, so it was **silently misclassifying filtered/firewalled ports as closed** — a meaningful accuracy bug for exactly the kind of host (firewalled, real-world) this tool is meant to be run against.

This rewrite classifies by exception type instead (`asyncio.TimeoutError` → filtered, `ConnectionRefusedError`/`ConnectionResetError` → closed, other `OSError` → filtered), verified against the same real target. Caught during this rewrite, before v1 was ever pushed publicly.

### Threads vs. asyncio: it's not a simple "asyncio is faster"

The initial motivation for rewriting the threaded engine as async was performance. The first async version was actually **slower** than the threaded original on a full 65,535-port localhost scan (~6–7s vs. ~2.3s). Root cause: it created one `asyncio.Task` per port up front — for a full port range, that's 65,535 live Task objects the event loop has to manage, even with a semaphore gating actual connections. That's real overhead a `ThreadPoolExecutor` doesn't have, since a thread pool only ever holds `N` worker threads and pulls from a plain queue regardless of how much work is behind it.

Fixed by switching to a **bounded worker-pool pattern** — a fixed number of long-lived worker coroutines pulling from a shared `asyncio.Queue`, mirroring how `ThreadPoolExecutor` stays cheap at scale. That closed most of the gap (~4.2–4.6s), but threads still edged out async on pure localhost throughput.

The reason turned out to be architecturally interesting rather than a bug: **localhost connections are close to zero-latency**, which makes this a CPU/syscall-bound workload, not an I/O-wait-bound one. Asyncio's advantage is letting the event loop do other work *while waiting* on I/O — but when there's essentially nothing to wait for, its own Python-level bookkeeping (Task/Future creation, callback scheduling) becomes pure overhead with no corresponding benefit, while OS threads doing a blocking syscall for an instant refusal pay comparatively little Python-level tax.

Tested against a real target with actual network latency (`scanme.nmap.org`, 1,024 ports) instead, the picture flips to what the theory predicts: at equal settings (`--no-retry`), the async and threaded engines finish in essentially identical time (22.07s vs. 22.03s) — but the async version is *correct* about filtered vs. closed, and scales to far higher concurrency without spawning a proportional number of OS threads (each idle thread has real memory/scheduling cost; an idle coroutine waiting on a timeout does not).

**Honest takeaway:** asyncio's real win here isn't raw localhost speed — it's scaling cleanly across many hosts/ports with real network latency, and doing so on a fraction of the resources a thread-per-connection model would need at the same concurrency.

### The retry-on-filtered tradeoff, quantified

Retrying a filtered result once (in case it was transient jitter rather than a real firewall rule) is more accurate but not free. Measured on the same 1,024-port `scanme.nmap.org` scan: **22.07s with `--no-retry` vs. 44.82s with retry enabled** — almost exactly 2x, since nearly every port on that host is genuinely filtered and pays the retry cost. Retry stays on by default (favoring correctness), but `--no-retry` is there deliberately for large scans where speed matters more than catching transient drops.

--- 
### A Windows-specific classification discrepancy, found via cross-platform testing

[#a-windows-specific-classification-discrepancy-found-via-cross-platform-testing](#a-windows-specific-classification-discrepancy-found-via-cross-platform-testing)

Testing the full suite on Windows 11 (vs. the Linux/macOS environment used for the benchmarks above) surfaced a genuine, reproducible platform difference: **3 of 93 tests fail on Windows**, all for the same root cause. Each test assumes an unbound loopback TCP port will be classified `closed` — true on Linux/macOS, where the kernel sends an immediate `RST` for a connection to a port nothing is listening on. On Windows, the same unbound port instead returned `filtered` (hit the full connection timeout rather than getting an instant refusal), most likely due to how Windows Firewall handles loopback traffic.

This isn't a bug in the classification logic — `scanner.py` correctly labels "no response within timeout" as `filtered`, exactly as designed. It's the *test's* cross-platform assumption that doesn't hold: "an unused port always refuses instantly" is a Linux/macOS-specific guarantee, not a universal one. Confirmed consistent across repeated runs (not flaky), so this is a legitimate platform difference worth documenting rather than an intermittent test issue.

**Resolution:** the shared `unused_port` fixture now skips on Windows with an explanatory reason, so the suite runs clean there (tests that depend on a refused connection are skipped, not failing) and still runs in full on Linux and macOS, which is what CI uses.

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest tests/ --cov=port_scanner --cov-report=term-missing
ruff check src/ tests/
```

93 tests, 96% coverage. Open/closed states are tested against real local sockets (an actual `asyncio` TCP server spun up per test, not mocked) for genuine end-to-end confidence. Filtered/timeout and retry logic are tested with deterministic mocking rather than real network conditions — a true "silently dropped" filtered state is inherently network-path-dependent (confirmed directly: neither `192.0.2.1`/TEST-NET-1 nor a private unreachable range behaved consistently across test runs in every environment), so relying on it for CI would make the suite flaky. Mocking the classification layer directly gives fast, portable, deterministic coverage of that logic instead.

CI runs the full suite plus lint on Python 3.10, 3.11, and 3.12, and separately verifies the packaged console script actually installs and runs cleanly in a fresh environment (the "works with `-e`, breaks on real install" class of bug is exactly what that catches).

---

## 🧩 Architecture

```
src/port_scanner/
├── models.py    # PortResult / HostResult dataclasses
├── ports.py     # Pure parsing: port specs, target specs (incl. CIDR), no I/O
├── scanner.py   # Async engine: DNS resolution, classification, banner grab, worker pool
├── output.py    # Terminal formatting (color-safe), JSON export, time estimation
├── cli.py       # argparse, interactive mode, orchestration
└── __main__.py  # `python -m port_scanner` entry point
```

`ports.py` is deliberately free of any I/O so its logic (CIDR expansion, range parsing) is trivial to unit test in isolation from anything network-related.

---

## 📊 Comparison to Nmap

This is not a substitute for Nmap, and pretending otherwise wouldn't do this project any favors. Nmap has ~25 years of development, raw-socket SYN scanning, OS fingerprinting, and thousands of service-detection signatures. For serious network reconnaissance, use Nmap.

Where this has real, distinct value instead:

- **As an embeddable Python library** — zero-dependency and stdlib-only, so `from port_scanner import scan_hosts` drops directly into another script or CI pipeline without shelling out to a separate binary.
- **As a demonstration of understanding** — this proves comprehension of TCP handshakes, async I/O, concurrency tradeoffs, and TLS at a level that "I ran `nmap -sV`" doesn't.
- **For quick checks with no install** — anywhere Python is already available but installing Nmap isn't an option.

## 🚫 Scope & Limitations

- **TCP only** — no UDP scanning (a fundamentally different mechanism)
- **No OS fingerprinting** — no equivalent to Nmap's `-O`
- **No SYN/stealth scanning** — uses a full `connect()`, not a half-open SYN scan, so it's easily logged and doesn't evade basic IDS. This is a deliberate simplicity tradeoff: SYN scanning needs raw sockets and elevated privileges, which would make the tool harder to just install and run.
- **No exploitation** — detects and reports only; never interacts with a service beyond reading its banner.

---

## 🎯 Goal

Built as part of a hands-on cybersecurity portfolio, alongside the [Password Security Analyzer](https://github.com/23rob/password-strength-checker), to demonstrate practical networking, concurrency, testing discipline, and honest performance analysis in Python.

## 📄 License

[MIT](LICENSE)
