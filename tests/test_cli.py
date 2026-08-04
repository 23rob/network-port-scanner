"""Tests for port_scanner.cli."""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import patch

import pytest

from port_scanner import cli


class TestBuildParser:
    def test_defaults(self):
        args = cli.build_parser().parse_args(["-t", "127.0.0.1"])
        assert args.target == "127.0.0.1"
        assert args.ports is None
        assert args.timeout == 1.0
        assert args.concurrency == 200
        assert args.banners is False
        assert args.no_retry is False
        assert args.output is None
        assert args.verbose is False
        assert args.quiet is False
        assert args.no_color is False
        assert args.yes is False

    def test_all_flags_parse(self):
        args = cli.build_parser().parse_args([
            "-t", "10.0.0.0/28",
            "-p", "22,80,443",
            "--timeout", "0.5",
            "--concurrency", "50",
            "--banners",
            "--no-retry",
            "-o", "out.json",
            "-v",
            "-q",
            "--no-color",
            "-y",
        ])
        assert args.target == "10.0.0.0/28"
        assert args.ports == "22,80,443"
        assert args.timeout == 0.5
        assert args.concurrency == 50
        assert args.banners is True
        assert args.no_retry is True
        assert args.output == "out.json"
        assert args.verbose is True
        assert args.quiet is True
        assert args.no_color is True
        assert args.yes is True

    def test_no_target_is_allowed_at_parse_time(self):
        # Target is optional at the parser level -- its absence is
        # what triggers interactive mode in main(), not a parse error.
        args = cli.build_parser().parse_args([])
        assert args.target is None

    def test_version_flag_exits_cleanly(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli.build_parser().parse_args(["--version"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "port-scanner" in out


class TestRunScanValidation:
    """Input-validation branches in _run_scan that should fail fast, before any I/O."""

    async def test_invalid_target_spec_returns_1(self, capsys):
        code = await cli._run_scan(
            target_spec="10.0.0.0/999", port_spec="80", timeout=1.0,
            concurrency=10, grab_banners=False, retry_filtered=True,
            output_file=None, verbose=False, quiet=True, no_color=True,
            assume_yes=True,
        )
        assert code == 1
        assert "Invalid CIDR" in capsys.readouterr().err

    async def test_invalid_port_spec_returns_1(self, capsys):
        code = await cli._run_scan(
            target_spec="127.0.0.1", port_spec="99999", timeout=1.0,
            concurrency=10, grab_banners=False, retry_filtered=True,
            output_file=None, verbose=False, quiet=True, no_color=True,
            assume_yes=True,
        )
        assert code == 1
        assert "out of valid range" in capsys.readouterr().err

    async def test_zero_concurrency_returns_1(self, capsys):
        code = await cli._run_scan(
            target_spec="127.0.0.1", port_spec="80", timeout=1.0,
            concurrency=0, grab_banners=False, retry_filtered=True,
            output_file=None, verbose=False, quiet=True, no_color=True,
            assume_yes=True,
        )
        assert code == 1
        assert "--concurrency" in capsys.readouterr().err

    async def test_zero_timeout_returns_1(self, capsys):
        code = await cli._run_scan(
            target_spec="127.0.0.1", port_spec="80", timeout=0,
            concurrency=10, grab_banners=False, retry_filtered=True,
            output_file=None, verbose=False, quiet=True, no_color=True,
            assume_yes=True,
        )
        assert code == 1
        assert "--timeout" in capsys.readouterr().err

    async def test_unresolvable_target_returns_1(self, capsys):
        code = await cli._run_scan(
            target_spec="totally-fake-xyz-123.invalid", port_spec="80", timeout=1.0,
            concurrency=10, grab_banners=False, retry_filtered=True,
            output_file=None, verbose=False, quiet=True, no_color=True,
            assume_yes=True,
        )
        assert code == 1
        assert "No targets could be resolved" in capsys.readouterr().err


class TestRunScanSuccess:
    async def test_successful_scan_returns_0(self, local_server, capsys):
        code = await cli._run_scan(
            target_spec=local_server.host, port_spec=str(local_server.port),
            timeout=2.0, concurrency=10, grab_banners=False, retry_filtered=True,
            output_file=None, verbose=False, quiet=True, no_color=True,
            assume_yes=True,
        )
        assert code == 0
        out = capsys.readouterr().out
        assert "OPEN" in out

    async def test_json_export_written(self, local_server):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            code = await cli._run_scan(
                target_spec=local_server.host, port_spec=str(local_server.port),
                timeout=2.0, concurrency=10, grab_banners=False, retry_filtered=True,
                output_file=path, verbose=False, quiet=True, no_color=True,
                assume_yes=True,
            )
            assert code == 0
            with open(path) as f:
                data = json.load(f)
            assert data["hosts_scanned"] == 1


class TestConfirmationGate:
    """Large-scan confirmation logic, using a mocked scan_hosts so these
    tests are fast and don't perform any real large scan."""

    async def _fake_scan_hosts(self, *args, **kwargs):
        return [], []

    async def test_large_scan_non_tty_refuses_without_yes(self, capsys):
        with patch("sys.stdin.isatty", return_value=False):
            code = await cli._run_scan(
                target_spec="127.0.0.1", port_spec="1-25000", timeout=1.0,
                concurrency=200, grab_banners=False, retry_filtered=True,
                output_file=None, verbose=False, quiet=True, no_color=True,
                assume_yes=False,
            )
        assert code == 1
        assert "Refusing" in capsys.readouterr().err

    async def test_large_scan_with_yes_flag_bypasses_prompt(self, local_server):
        # concurrency/port spec chosen so total_probes exceeds the
        # threshold, but scan_hosts is mocked so it resolves instantly
        # instead of actually scanning 25,000 ports.
        with patch.object(cli, "scan_hosts", self._fake_scan_hosts):
            code = await cli._run_scan(
                target_spec="127.0.0.1", port_spec="1-25000", timeout=1.0,
                concurrency=200, grab_banners=False, retry_filtered=True,
                output_file=None, verbose=False, quiet=True, no_color=True,
                assume_yes=True,
            )
        # empty hosts result -> "no targets resolved" path -> 1, but
        # the key thing under test is that it got PAST the confirmation
        # gate at all rather than refusing outright.
        assert code == 1  # from the empty fake result, not from the gate

    async def test_large_scan_interactive_accept(self):
        with patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", return_value="y"), \
             patch.object(cli, "scan_hosts", self._fake_scan_hosts):
            code = await cli._run_scan(
                target_spec="127.0.0.1", port_spec="1-25000", timeout=1.0,
                concurrency=200, grab_banners=False, retry_filtered=True,
                output_file=None, verbose=False, quiet=True, no_color=True,
                assume_yes=False,
            )
        assert code == 1  # got past the gate, then hit empty-result path

    async def test_large_scan_interactive_decline(self, capsys):
        with patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", return_value="n"):
            code = await cli._run_scan(
                target_spec="127.0.0.1", port_spec="1-25000", timeout=1.0,
                concurrency=200, grab_banners=False, retry_filtered=True,
                output_file=None, verbose=False, quiet=True, no_color=True,
                assume_yes=False,
            )
        assert code == 130
        assert "cancelled" in capsys.readouterr().out.lower()


class TestRunInteractive:
    async def test_interactive_flow_with_defaults(self, local_server, capsys):
        inputs = iter([local_server.host, str(local_server.port), "n"])
        with patch("builtins.input", lambda _: next(inputs)):
            code = await cli.run_interactive()
        assert code == 0
        out = capsys.readouterr().out
        assert "Interactive Mode" in out
        assert "OPEN" in out

    async def test_interactive_uses_top_ports_when_blank(self, local_server):
        # Empty port input should fall back to the top-ports default
        # rather than erroring.
        inputs = iter([local_server.host, "", "n"])
        with patch("builtins.input", lambda _: next(inputs)):
            code = await cli.run_interactive()
        assert code == 0


class TestMain:
    def test_main_with_target_runs_scan(self, local_server, capsys):
        code = cli.main([
            "-t", local_server.host, "-p", str(local_server.port),
            "-q", "--no-color",
        ])
        assert code == 0
        assert "OPEN" in capsys.readouterr().out

    def test_main_invalid_args_nonzero_exit(self):
        code = cli.main(["-t", "127.0.0.1", "--concurrency", "0"])
        assert code == 1

    def test_main_no_target_enters_interactive_mode(self, local_server):
        inputs = iter([local_server.host, str(local_server.port), "n"])
        with patch("builtins.input", lambda _: next(inputs)):
            code = cli.main([])
        assert code == 0

    def test_keyboard_interrupt_returns_130(self):
        async def _raise_interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        # Patch _run_scan itself (not asyncio.run) so the coroutine
        # actually gets awaited and raises from within real execution
        # -- patching asyncio.run directly would construct the
        # _run_scan(...) coroutine and then never consume it, leaving
        # a "coroutine was never awaited" warning.
        with patch.object(cli, "_run_scan", _raise_interrupt):
            code = cli.main(["-t", "127.0.0.1"])
        assert code == 130
