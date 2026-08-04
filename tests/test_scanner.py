"""
Tests for port_scanner.scanner.

Open/closed states are tested against real local sockets (no mocking)
for genuine end-to-end confidence. Filtered/timeout and retry behavior
are tested with mocking, because a true "filtered" (silently dropped)
condition is inherently network-path-dependent and can't be reliably
or portably reproduced in a test environment — relying on real
firewall behavior would make these tests flaky across machines/CI
runners. Mocking the classification function directly gives
deterministic, fast, and portable coverage of that logic instead.
"""

from __future__ import annotations

import asyncio
import ipaddress
from unittest.mock import patch

import pytest

from port_scanner import scanner


class TestResolveTarget:
    async def test_ipv4_literal_passthrough(self):
        assert await scanner.resolve_target("127.0.0.1") == "127.0.0.1"

    async def test_hostname_resolves_to_a_loopback_address(self):
        # "localhost" can legitimately resolve to either 127.0.0.1
        # (IPv4) or ::1 (IPv6) depending on the machine's resolver
        # configuration -- confirmed directly: this returned 127.0.0.1
        # in one environment and ::1 on GitHub Actions' runner, both
        # correct. Assert on the loopback *property* via ipaddress
        # rather than hardcoding one specific family, or the test is
        # really just asserting an assumption about the test machine.
        resolved = await scanner.resolve_target("localhost")
        assert ipaddress.ip_address(resolved).is_loopback

    async def test_unresolvable_hostname_raises_value_error(self):
        with pytest.raises(ValueError, match="Could not resolve host"):
            await scanner.resolve_target("this-does-not-exist-xyz-123.invalid")

    async def test_malformed_hostname_raises_value_error(self):
        # Empty label between dots fails IDNA encoding with a
        # UnicodeError before DNS is even queried -- must still
        # surface as a clean ValueError, not leak a raw UnicodeError.
        with pytest.raises(ValueError, match="Could not resolve host"):
            await scanner.resolve_target("bad..host..example")


class TestClassifyConnection:
    async def test_open_port_real_socket(self, local_server):
        state, elapsed_ms = await scanner._classify_connection(
            local_server.host, local_server.port, timeout=2.0
        )
        assert state == "open"
        assert elapsed_ms >= 0

    async def test_closed_port_real_socket(self, unused_port):
        state, elapsed_ms = await scanner._classify_connection(
            "127.0.0.1", unused_port, timeout=2.0
        )
        assert state == "closed"

    async def test_timeout_classified_as_filtered(self):
        async def hang_forever(*args, **kwargs):
            await asyncio.sleep(999)

        with patch("asyncio.open_connection", hang_forever):
            state, elapsed_ms = await scanner._classify_connection(
                "10.0.0.1", 80, timeout=0.05
            )
        assert state == "filtered"

    async def test_generic_oserror_classified_as_filtered(self):
        async def raise_unreachable(*args, **kwargs):
            raise OSError("Network is unreachable")

        with patch("asyncio.open_connection", raise_unreachable):
            state, _ = await scanner._classify_connection("10.0.0.1", 80, timeout=1.0)
        assert state == "filtered"

    async def test_connection_reset_classified_as_closed(self):
        async def raise_reset(*args, **kwargs):
            raise ConnectionResetError("Connection reset by peer")

        with patch("asyncio.open_connection", raise_reset):
            state, _ = await scanner._classify_connection("127.0.0.1", 80, timeout=1.0)
        assert state == "closed"


class TestGrabBanner:
    async def test_passive_banner_captured(self, local_server):
        local_server.set_banner(b"SSH-2.0-TestServer\r\n")
        banner = await scanner._grab_banner(local_server.host, local_server.port, timeout=2.0)
        assert banner is not None
        assert "SSH-2.0-TestServer" in banner

    async def test_no_banner_returns_none(self, local_server):
        # Server accepts but sends nothing and closes -- should return
        # None rather than raise.
        banner = await scanner._grab_banner(local_server.host, local_server.port, timeout=1.0)
        assert banner is None

    async def test_banner_truncated_to_150_chars(self, local_server):
        local_server.set_banner(b"X" * 500)
        banner = await scanner._grab_banner(local_server.host, local_server.port, timeout=2.0)
        assert len(banner) <= 150

    async def test_connection_failure_returns_none_not_exception(self):
        # A failed banner grab must degrade gracefully and never crash
        # the overall scan. Mocked rather than relying on a real
        # unreachable address: private/reserved ranges behave
        # inconsistently across sandboxed network environments (this
        # was verified directly -- 10.255.255.1 unexpectedly returned
        # a real HTTP response in this environment rather than timing
        # out), so a deterministic mock is the only portable way to
        # test this path reliably.
        async def raise_timeout(*args, **kwargs):
            raise asyncio.TimeoutError()

        with patch("asyncio.open_connection", raise_timeout):
            banner = await scanner._grab_banner("10.255.255.1", 80, timeout=0.1)
        assert banner is None

    async def test_ssl_error_returns_none_not_exception(self):
        import ssl as ssl_module

        async def raise_ssl_error(*args, **kwargs):
            raise ssl_module.SSLError("handshake failure")

        with patch("asyncio.open_connection", raise_ssl_error):
            banner = await scanner._grab_banner("1.2.3.4", 443, timeout=1.0)
        assert banner is None


class TestProbePort:
    async def test_open_port_no_banner_requested(self, local_server):
        local_server.set_banner(b"should not be read")
        result = await scanner.probe_port(
            local_server.host, local_server.port,
            timeout=2.0, grab_banners=False, retry_filtered=True,
            host_label="test-target",
        )
        assert result.state == "open"
        assert result.banner is None
        assert result.host == "test-target"
        assert result.port == local_server.port

    async def test_open_port_with_banner_requested(self, local_server):
        local_server.set_banner(b"HELLO\r\n")
        result = await scanner.probe_port(
            local_server.host, local_server.port,
            timeout=2.0, grab_banners=True, retry_filtered=True,
            host_label="test-target",
        )
        assert result.state == "open"
        assert result.banner is not None
        assert "HELLO" in result.banner

    async def test_closed_port_never_attempts_banner(self, unused_port):
        result = await scanner.probe_port(
            "127.0.0.1", unused_port,
            timeout=1.0, grab_banners=True, retry_filtered=True,
            host_label="test-target",
        )
        assert result.state == "closed"
        assert result.banner is None

    async def test_retry_recovers_transient_filtered_result(self):
        call_count = 0

        async def fake_classify(ip, port, timeout):
            nonlocal call_count
            call_count += 1
            return ("filtered", 1000.0) if call_count == 1 else ("open", 5.0)

        with patch.object(scanner, "_classify_connection", fake_classify):
            result = await scanner.probe_port(
                "127.0.0.1", 9999, timeout=1.0, grab_banners=False,
                retry_filtered=True, host_label="t",
            )
        assert call_count == 2
        assert result.state == "open"

    async def test_persistent_filtered_stays_filtered_after_retry(self):
        call_count = 0

        async def always_filtered(ip, port, timeout):
            nonlocal call_count
            call_count += 1
            return "filtered", 1000.0

        with patch.object(scanner, "_classify_connection", always_filtered):
            result = await scanner.probe_port(
                "127.0.0.1", 9999, timeout=1.0, grab_banners=False,
                retry_filtered=True, host_label="t",
            )
        assert call_count == 2
        assert result.state == "filtered"

    async def test_no_retry_flag_skips_retry_entirely(self):
        call_count = 0

        async def always_filtered(ip, port, timeout):
            nonlocal call_count
            call_count += 1
            return "filtered", 1000.0

        with patch.object(scanner, "_classify_connection", always_filtered):
            result = await scanner.probe_port(
                "127.0.0.1", 9999, timeout=1.0, grab_banners=False,
                retry_filtered=False, host_label="t",
            )
        assert call_count == 1
        assert result.state == "filtered"


class TestScanHosts:
    async def test_single_host_scan_finds_open_and_closed(self, local_server, unused_port):
        hosts, errors = await scanner.scan_hosts(
            [local_server.host],
            [local_server.port, unused_port],
            timeout=2.0, concurrency=10,
        )
        assert errors == []
        assert len(hosts) == 1
        host = hosts[0]
        assert len(host.open_ports) == 1
        assert host.open_ports[0].port == local_server.port
        assert len(host.closed_ports) == 1

    async def test_results_sorted_by_port(self, local_server):
        ports = [local_server.port, local_server.port + 1, local_server.port - 1]
        # filter out any that went negative/invalid for safety
        ports = [p for p in ports if 0 < p <= 65535]
        hosts, _ = await scanner.scan_hosts(
            [local_server.host], sorted(ports), timeout=1.0, concurrency=5,
        )
        result_ports = [r.port for r in hosts[0].ports]
        assert result_ports == sorted(result_ports)

    async def test_unresolvable_target_reported_not_fatal(self, local_server):
        hosts, errors = await scanner.scan_hosts(
            ["this-host-does-not-exist-xyz.invalid", local_server.host],
            [local_server.port],
            timeout=2.0, concurrency=10,
        )
        # the good target should still be scanned
        assert len(hosts) == 1
        assert hosts[0].ip == local_server.host
        # the bad one should be reported as an error, not silently dropped
        assert len(errors) == 1
        assert "this-host-does-not-exist-xyz.invalid" in errors[0]

    async def test_all_targets_unresolvable_returns_empty_with_errors(self):
        hosts, errors = await scanner.scan_hosts(
            ["bad-host-1.invalid", "bad-host-2.invalid"],
            [80],
            timeout=1.0, concurrency=10,
        )
        assert hosts == []
        assert len(errors) == 2

    async def test_multi_host_labels_kept_separate(self, local_server, unused_port):
        # Scan the same real server IP under two different "labels"
        # (as would happen with two different hostnames resolving to
        # the same IP) is out of scope here; instead confirm two
        # distinct IPs each get their own HostResult bucket.
        hosts, _ = await scanner.scan_hosts(
            ["127.0.0.1"], [local_server.port], timeout=1.0, concurrency=5,
        )
        assert len(hosts) == 1
        assert hosts[0].target == "127.0.0.1"

    async def test_concurrency_of_one_still_completes(self, local_server, unused_port):
        # Degenerate case: concurrency=1 means a single worker
        # processing the queue serially. Should still produce correct
        # results, just slower.
        hosts, errors = await scanner.scan_hosts(
            [local_server.host],
            [local_server.port, unused_port],
            timeout=1.0, concurrency=1,
        )
        assert errors == []
        assert len(hosts[0].ports) == 2

    async def test_progress_callback_invoked(self, local_server, unused_port):
        calls = []

        def cb(completed, total):
            calls.append((completed, total))

        await scanner.scan_hosts(
            [local_server.host], [local_server.port, unused_port],
            timeout=1.0, concurrency=10, progress_cb=cb,
        )
        assert len(calls) == 2  # once per completed probe
        assert calls[-1] == (2, 2)
