"""
Parsing helpers for target and port specifications.

Deliberately free of any I/O (no sockets, no DNS) so these functions are
trivial to unit test in isolation.
"""

from __future__ import annotations

import ipaddress

# Upper bound on how many hosts a single CIDR block is allowed to expand
# to. This exists purely as a safety rail so a typo like "10.0.0.0/8"
# doesn't silently attempt a 16-million-host scan.
MAX_CIDR_HOSTS = 65536

# Common ports -> service name. Used both for labeling results and as
# the default set for --top-ports.
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP (Submission)",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP / Flask-dev",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9000: "PHP-FPM / SonarQube",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

HTTP_PORTS = {80, 8080, 8000}
HTTPS_PORTS = {443, 8443}


def build_top_ports_string() -> str:
    """Comma-joined string of every port in COMMON_PORTS, for use as a default."""
    return ",".join(str(p) for p in sorted(COMMON_PORTS))


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


def parse_ports(port_spec: str) -> list[int]:
    """
    Parse a port specification string into a sorted list of unique ports.

    Accepts:
      "80"               -> [80]
      "22,80,443"        -> [22, 80, 443]
      "1-1024"           -> [1, 2, ..., 1024]
      "22,80,1000-1010"  -> mixed
    Reversed ranges (e.g. "10-5") are silently normalized.
    """
    ports: set[int] = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    invalid = [p for p in ports if not (0 < p <= 65535)]
    if invalid:
        raise ValueError(f"Ports out of valid range (1-65535): {sorted(invalid)}")

    return sorted(ports)


def parse_targets(target_spec: str) -> list[str]:
    """
    Parse a comma-separated target specification into a flat list of
    hostnames/IPs, expanding any CIDR entries into their individual
    host addresses.

    Accepts:
      "192.168.1.10"                    -> ["192.168.1.10"]
      "example.com"                     -> ["example.com"]
      "192.168.1.0/30"                  -> usable hosts in that block
      "10.0.0.1,10.0.0.2"                -> both, as given
      "192.168.1.0/29,scanme.example.com" -> mixed CIDR + hostname

    Raises ValueError on malformed CIDR notation or a CIDR block that
    would expand past MAX_CIDR_HOSTS.
    """
    targets: list[str] = []
    for chunk in target_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue

        if "/" in chunk:
            try:
                network = ipaddress.ip_network(chunk, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR notation '{chunk}': {exc}") from exc

            if network.num_addresses == 1:
                # e.g. /32 (IPv4) or /128 (IPv6) - a single address.
                host_list = [network.network_address]
            elif network.prefixlen in (31, 127):
                # Point-to-point blocks: both addresses are usable,
                # there's no separate network/broadcast address.
                host_list = list(network)
            else:
                host_list = list(network.hosts())

            if len(host_list) > MAX_CIDR_HOSTS:
                raise ValueError(
                    f"CIDR block '{chunk}' expands to {len(host_list)} hosts, "
                    f"which exceeds the safety limit of {MAX_CIDR_HOSTS}. "
                    f"Use a smaller block."
                )

            targets.extend(str(ip) for ip in host_list)
        else:
            targets.append(chunk)

    return targets
