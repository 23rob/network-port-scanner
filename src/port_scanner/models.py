"""Data models shared across the scanner package."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PortResult:
    """The outcome of probing a single port on a single host."""

    host: str
    port: int
    state: str  # "open", "closed", or "filtered"
    service: str
    banner: str | None = None
    response_ms: float | None = None


@dataclass
class HostResult:
    """All port results for a single scanned host, plus a resolved label."""

    target: str          # what the user typed (hostname, IP, or CIDR member)
    ip: str               # resolved IP actually scanned
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def closed_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "closed"]

    @property
    def filtered_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "filtered"]
