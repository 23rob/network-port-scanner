"""
port_scanner
============

An async, multi-host TCP port scanner for authorized security testing.

Public API:
    scan_hosts(targets, ports, ...) -> (host_results, resolution_errors)
    parse_targets(spec) -> list[str]
    parse_ports(spec) -> list[int]
"""

from .models import HostResult, PortResult
from .ports import COMMON_PORTS, parse_ports, parse_targets
from .scanner import scan_hosts

__version__ = "2.0.0"

__all__ = [
    "__version__",
    "scan_hosts",
    "parse_targets",
    "parse_ports",
    "COMMON_PORTS",
    "HostResult",
    "PortResult",
]
