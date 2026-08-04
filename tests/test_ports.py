"""Tests for port_scanner.ports — pure parsing functions, no I/O."""

import pytest

from port_scanner.ports import (
    build_top_ports_string,
    parse_ports,
    parse_targets,
    service_name,
)


class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_comma_list(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        assert parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_mixed(self):
        assert parse_ports("22,80,1000-1003") == [22, 80, 1000, 1001, 1002, 1003]

    def test_single_element_range(self):
        assert parse_ports("100-100") == [100]

    def test_reversed_range_is_normalized(self):
        assert parse_ports("10-5") == [5, 6, 7, 8, 9, 10]

    def test_duplicates_are_deduplicated(self):
        assert parse_ports("80,80,80") == [80]

    def test_overlapping_range_and_list_deduplicated(self):
        assert parse_ports("1-5,3,4,5") == [1, 2, 3, 4, 5]

    def test_whitespace_tolerated(self):
        assert parse_ports(" 22, 80 , 443 ") == [22, 80, 443]

    def test_rejects_port_zero(self):
        with pytest.raises(ValueError, match="out of valid range"):
            parse_ports("0")

    def test_rejects_port_above_65535(self):
        with pytest.raises(ValueError, match="out of valid range"):
            parse_ports("70000")

    def test_rejects_negative_via_range_component(self):
        with pytest.raises(ValueError):
            parse_ports("-5-10")


class TestParseTargets:
    def test_single_ip(self):
        assert parse_targets("192.168.1.10") == ["192.168.1.10"]

    def test_single_hostname(self):
        assert parse_targets("example.com") == ["example.com"]

    def test_comma_separated(self):
        assert parse_targets("10.0.0.1,10.0.0.2") == ["10.0.0.1", "10.0.0.2"]

    def test_cidr_slash_30_excludes_network_and_broadcast(self):
        # A /30 has 4 addresses total; only the middle 2 are "usable hosts".
        result = parse_targets("192.168.1.0/30")
        assert result == ["192.168.1.1", "192.168.1.2"]

    def test_cidr_slash_29_six_hosts(self):
        result = parse_targets("192.168.1.0/29")
        assert result == [f"192.168.1.{i}" for i in range(1, 7)]

    def test_cidr_slash_32_is_single_host(self):
        assert parse_targets("192.168.1.5/32") == ["192.168.1.5"]

    def test_cidr_slash_31_point_to_point_both_usable(self):
        # /31 is a special case (RFC 3021): no network/broadcast concept,
        # both addresses are valid hosts.
        result = parse_targets("192.168.1.0/31")
        assert result == ["192.168.1.0", "192.168.1.1"]

    def test_mixed_cidr_and_hostname(self):
        result = parse_targets("192.168.1.0/30,example.com")
        assert result == ["192.168.1.1", "192.168.1.2", "example.com"]

    def test_invalid_cidr_raises(self):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            parse_targets("192.168.1.0/99")

    def test_oversized_cidr_is_rejected(self):
        with pytest.raises(ValueError, match="exceeds the safety limit"):
            parse_targets("10.0.0.0/8")

    def test_whitespace_tolerated(self):
        assert parse_targets(" 10.0.0.1 , 10.0.0.2 ") == ["10.0.0.1", "10.0.0.2"]

    def test_empty_chunks_ignored(self):
        assert parse_targets("10.0.0.1,,10.0.0.2,") == ["10.0.0.1", "10.0.0.2"]


class TestServiceName:
    def test_known_port(self):
        assert service_name(22) == "SSH"
        assert service_name(443) == "HTTPS"

    def test_unknown_port(self):
        assert service_name(54321) == "unknown"


class TestTopPortsString:
    def test_returns_comma_separated_string(self):
        s = build_top_ports_string()
        assert "," in s
        # every entry should parse back to an int
        for chunk in s.split(","):
            int(chunk)

    def test_matches_parse_ports_round_trip(self):
        s = build_top_ports_string()
        ports = parse_ports(s)
        assert len(ports) > 40  # sanity check we have a real list, not a stub
        assert all(0 < p <= 65535 for p in ports)
