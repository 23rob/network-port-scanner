"""Command-line interface for the port scanner."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time

from . import __version__
from .output import (
    color_enabled,
    export_json,
    make_progress_printer,
    print_final_summary,
    print_host_report,
    print_pre_scan_summary,
)
from .ports import build_top_ports_string, parse_ports, parse_targets
from .scanner import scan_hosts

# Scans above this many total probes require an explicit confirmation
# (or --yes) before running, since they can take a while and may be
# noticeable on the target network.
CONFIRM_THRESHOLD = 20_000


async def _run_scan(
    *,
    target_spec: str,
    port_spec: str,
    timeout: float,
    concurrency: int,
    grab_banners: bool,
    retry_filtered: bool,
    output_file: str | None,
    verbose: bool,
    quiet: bool,
    no_color: bool,
    assume_yes: bool,
) -> int:
    try:
        targets = parse_targets(target_spec)
        port_list = parse_ports(port_spec)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    if concurrency < 1:
        print("[!] --concurrency must be at least 1", file=sys.stderr)
        return 1
    if timeout <= 0:
        print("[!] --timeout must be greater than 0", file=sys.stderr)
        return 1

    total_probes = len(targets) * len(port_list)
    if not quiet:
        print_pre_scan_summary(len(targets), len(port_list), concurrency, timeout)

    if total_probes > CONFIRM_THRESHOLD and not assume_yes:
        if not sys.stdin.isatty():
            print(
                f"[!] Refusing to run a {total_probes}-probe scan without "
                f"confirmation in a non-interactive session. Pass --yes to proceed.",
                file=sys.stderr,
            )
            return 1
        resp = input(
            f"This scan involves {total_probes} probes and may take a while "
            f"or be noticeable on the target network. Continue? [y/N] "
        ).strip().lower()
        if resp != "y":
            print("Scan cancelled.")
            return 130

    use_color = color_enabled(no_color)
    progress_cb = make_progress_printer(quiet)

    start = time.perf_counter()
    hosts, resolution_errors = await scan_hosts(
        targets, port_list,
        timeout=timeout,
        concurrency=concurrency,
        grab_banners=grab_banners,
        retry_filtered=retry_filtered,
        progress_cb=progress_cb,
    )
    elapsed = time.perf_counter() - start

    if not hosts:
        print("[!] No targets could be resolved. Nothing was scanned.", file=sys.stderr)
        for err in resolution_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    for host in hosts:
        print_host_report(host, verbose=verbose, use_color=use_color)

    print_final_summary(hosts, resolution_errors, elapsed)

    if output_file:
        export_json(hosts, resolution_errors, elapsed, output_file)

    return 0


async def run_interactive() -> int:
    print("=" * 60)
    print(" Network Port Scanner — Interactive Mode")
    print("=" * 60)
    print("⚠️  Only scan hosts/networks you own or have permission to test.")
    print("    (Single host, comma list, or CIDR e.g. 192.168.1.0/28 all work.)\n")

    target = input("Target(s): ").strip()
    port_spec = input(
        "Ports (e.g. 1-1024, 22,80,443) [default: top ports]: "
    ).strip() or build_top_ports_string()
    grab_banners = input("Grab service banners? (y/N): ").strip().lower() == "y"

    return await _run_scan(
        target_spec=target,
        port_spec=port_spec,
        timeout=1.0,
        concurrency=200,
        grab_banners=grab_banners,
        retry_filtered=True,
        output_file=None,
        verbose=True,
        quiet=False,
        no_color=False,
        assume_yes=False,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description="Async, multi-host TCP port scanner for authorized security testing.",
        epilog=(
            "Examples:\n"
            "  port-scanner -t 192.168.1.10 -p 1-1024 --banners\n"
            "  port-scanner -t 192.168.1.0/28 --top-ports\n"
            "  port-scanner -t 10.0.0.5,10.0.0.6 -p 22,80,443 -o results.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target",
                         help="Target(s): hostname, IP, comma list, and/or CIDR "
                              "(e.g. 192.168.1.0/28). Omit for interactive mode.")
    parser.add_argument("-p", "--ports", default=None,
                         help="Ports: '80', '22,80,443', '1-1024', or combinations. "
                              "Defaults to a built-in common-ports set.")
    parser.add_argument("--top-ports", action="store_true",
                         help="Explicitly scan the built-in common/well-known ports set.")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Per-port connection timeout in seconds (default: 1.0)")
    parser.add_argument("--concurrency", type=int, default=200,
                         help="Max concurrent in-flight connections (default: 200)")
    parser.add_argument("--banners", action="store_true",
                         help="Attempt to grab service banners on open ports.")
    parser.add_argument("--no-retry", action="store_true",
                         help="Disable the single automatic retry on filtered results.")
    parser.add_argument("-o", "--output", metavar="FILE",
                         help="Export results as JSON to FILE.")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show filtered/non-responsive ports too.")
    parser.add_argument("-q", "--quiet", action="store_true",
                         help="Suppress the progress indicator and pre-scan summary.")
    parser.add_argument("--no-color", action="store_true",
                         help="Disable colored output.")
    parser.add_argument("-y", "--yes", action="store_true",
                         help="Skip the confirmation prompt for very large scans.")
    parser.add_argument("--version", action="version",
                         version=f"port-scanner {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if not args.target:
            return asyncio.run(run_interactive())

        port_spec = args.ports or build_top_ports_string()
        return asyncio.run(_run_scan(
            target_spec=args.target,
            port_spec=port_spec,
            timeout=args.timeout,
            concurrency=args.concurrency,
            grab_banners=args.banners,
            retry_filtered=not args.no_retry,
            output_file=args.output,
            verbose=args.verbose,
            quiet=args.quiet,
            no_color=args.no_color,
            assume_yes=args.yes,
        ))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
