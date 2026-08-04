"""Terminal and JSON output formatting."""

from __future__ import annotations

import json
import math
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone

from .models import HostResult

_COLOR_CODES = {
    "open": "\033[32m",      # green
    "closed": "\033[90m",    # dim gray
    "filtered": "\033[33m",  # yellow
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def color_enabled(no_color_flag: bool, stream=sys.stdout) -> bool:
    """
    Decide whether ANSI colors should be used.

    Respects, in order: an explicit --no-color flag, the NO_COLOR
    environment variable convention (https://no-color.org/), and
    whether the output stream is actually a terminal (colors are
    suppressed automatically when output is piped/redirected, e.g.
    into a file or `| less`).
    """
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def _c(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLOR_CODES.get(color, '')}{text}{_COLOR_CODES['reset']}"


def estimate_scan_time(total_probes: int, concurrency: int, timeout: float) -> float:
    """
    A conservative *upper bound* on scan duration: how long it would
    take if every single probe had to wait out the full timeout. Real
    scans are almost always much faster since open/closed ports
    respond quickly — only filtered ports pay the full timeout.
    """
    rounds = math.ceil(total_probes / max(concurrency, 1))
    return rounds * timeout


def print_pre_scan_summary(
    num_hosts: int, num_ports: int, concurrency: int, timeout: float,
) -> int:
    """Prints the pre-scan estimate banner and returns total probe count."""
    total = num_hosts * num_ports
    est = estimate_scan_time(total, concurrency, timeout)
    print(
        f"Targets: {num_hosts} host(s) x {num_ports} port(s) = {total} probe(s) | "
        f"concurrency={concurrency} | timeout={timeout}s | "
        f"worst-case upper bound: ~{est:.1f}s (typically much faster)",
        file=sys.stderr,
    )
    return total


def make_progress_printer(quiet: bool):
    """Returns a progress_cb(completed, total) suitable for scan_hosts()."""
    if quiet:
        return None

    def _cb(completed: int, total: int) -> None:
        if completed % 50 == 0 or completed == total:
            pct = completed / total * 100 if total else 100
            print(f"\r  Scanning... {completed}/{total} probes ({pct:.0f}%)",
                  end="", file=sys.stderr, flush=True)
            if completed == total:
                print(file=sys.stderr)

    return _cb


def print_host_report(host: HostResult, verbose: bool, use_color: bool) -> None:
    print(f"\nScan Report for {host.target} ({host.ip})")
    print("=" * 60)

    if host.open_ports:
        print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<20}{'BANNER'}")
        print("-" * 60)
        for r in host.open_ports:
            # Pad the plain text to its visible width FIRST, then wrap
            # in color codes — coloring an already-padded string keeps
            # alignment correct whether or not color ends up enabled,
            # since ANSI escape bytes would otherwise be counted by
            # str.format's padding and throw columns off when color
            # is disabled (the common case: piped output, --no-color).
            state_label = _c(r.state.upper().ljust(10), "open", use_color)
            banner_str = r.banner or ""
            print(f"{r.port:<10}{state_label}{r.service:<20}{banner_str}")
    else:
        print("No open ports found.")

    if verbose and host.filtered_ports:
        filtered_str = _c(
            ", ".join(str(r.port) for r in host.filtered_ports), "filtered", use_color
        )
        print(f"\n{len(host.filtered_ports)} port(s) filtered "
              f"(no response / firewalled): {filtered_str}")

    print("-" * 60)
    print(
        f"{len(host.ports)} port(s) scanned | "
        f"{_c(str(len(host.open_ports)) + ' open', 'open', use_color)}, "
        f"{_c(str(len(host.closed_ports)) + ' closed', 'closed', use_color)}, "
        f"{_c(str(len(host.filtered_ports)) + ' filtered', 'filtered', use_color)}"
    )


def print_final_summary(
    hosts: list[HostResult],
    resolution_errors: list[str],
    elapsed: float,
) -> None:
    total_open = sum(len(h.open_ports) for h in hosts)
    total_ports = sum(len(h.ports) for h in hosts)
    print(f"\n{'=' * 60}")
    print(
        f"Scan complete: {len(hosts)} host(s), {total_ports} total port(s) "
        f"scanned in {elapsed:.2f}s | {total_open} open port(s) found"
    )
    if resolution_errors:
        print(f"\n{len(resolution_errors)} target(s) could not be resolved:")
        for err in resolution_errors:
            print(f"  - {err}")


def export_json(
    hosts: list[HostResult],
    resolution_errors: list[str],
    elapsed: float,
    filename: str,
) -> None:
    payload = {
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(elapsed, 3),
        "hosts_scanned": len(hosts),
        "resolution_errors": resolution_errors,
        "results": [
            {
                "target": h.target,
                "ip": h.ip,
                "open_ports": len(h.open_ports),
                "ports": [asdict(p) for p in h.ports],
            }
            for h in hosts
        ],
    }
    with open(filename, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n[+] Results exported to {filename}")
