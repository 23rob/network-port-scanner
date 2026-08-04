"""Tests for port_scanner.output."""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import patch

from port_scanner.models import HostResult, PortResult
from port_scanner.output import (
    color_enabled,
    estimate_scan_time,
    export_json,
    print_final_summary,
    print_host_report,
)


class FakeStream:
    """A minimal stand-in for sys.stdout with a controllable isatty()."""

    def __init__(self, is_tty: bool):
        self._is_tty = is_tty

    def isatty(self):
        return self._is_tty


class TestColorEnabled:
    def test_no_color_flag_forces_off(self):
        assert color_enabled(no_color_flag=True, stream=FakeStream(True)) is False

    def test_disabled_when_not_a_tty(self):
        assert color_enabled(no_color_flag=False, stream=FakeStream(False)) is False

    def test_enabled_when_tty_and_flag_not_set(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            assert color_enabled(no_color_flag=False, stream=FakeStream(True)) is True

    def test_no_color_env_var_respected(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            assert color_enabled(no_color_flag=False, stream=FakeStream(True)) is False

    def test_stream_without_isatty_defaults_to_no_color(self):
        class NoIsAtty:
            pass

        assert color_enabled(no_color_flag=False, stream=NoIsAtty()) is False


class TestEstimateScanTime:
    def test_single_round(self):
        # 50 probes, concurrency 100 -> everyone fits in one round
        assert estimate_scan_time(total_probes=50, concurrency=100, timeout=1.0) == 1.0

    def test_multiple_rounds(self):
        # 250 probes, concurrency 100 -> ceil(250/100) = 3 rounds
        assert estimate_scan_time(total_probes=250, concurrency=100, timeout=2.0) == 6.0

    def test_zero_concurrency_does_not_divide_by_zero(self):
        # Should clamp to at least 1 internally rather than crashing.
        result = estimate_scan_time(total_probes=10, concurrency=0, timeout=1.0)
        assert result == 10.0


class TestPrintHostReport:
    def _make_host(self):
        return HostResult(
            target="example.com",
            ip="1.2.3.4",
            ports=[
                PortResult(host="example.com", port=22, state="open",
                           service="SSH", banner="SSH-2.0-Test"),
                PortResult(host="example.com", port=23, state="closed", service="Telnet"),
                PortResult(host="example.com", port=24, state="filtered", service="unknown"),
            ],
        )

    def test_no_color_alignment_matches_header_width(self, capsys):
        print_host_report(self._make_host(), verbose=False, use_color=False)
        out = capsys.readouterr().out
        lines = out.splitlines()
        header_line = next(line for line in lines if line.startswith("PORT"))
        data_line = next(line for line in lines if line.startswith("22"))
        # "SERVICE" in the header and the service name in the data row
        # should land in the same column when color is off.
        assert header_line.index("SERVICE") == data_line.index("SSH")

    def test_color_does_not_break_visible_alignment(self, capsys):
        print_host_report(self._make_host(), verbose=False, use_color=True)
        out = capsys.readouterr().out
        # Strip ANSI codes and confirm the same alignment invariant
        # holds regardless of the invisible color bytes.
        import re
        stripped = re.sub(r"\033\[[0-9;]*m", "", out)
        lines = stripped.splitlines()
        header_line = next(line for line in lines if line.startswith("PORT"))
        data_line = next(line for line in lines if line.startswith("22"))
        assert header_line.index("SERVICE") == data_line.index("SSH")

    def test_closed_ports_not_listed_in_table(self, capsys):
        print_host_report(self._make_host(), verbose=False, use_color=False)
        out = capsys.readouterr().out
        # Only the open port's row should appear; port 23 (closed)
        # shouldn't get its own table row.
        assert "23        " not in out

    def test_verbose_shows_filtered_ports(self, capsys):
        print_host_report(self._make_host(), verbose=True, use_color=False)
        out = capsys.readouterr().out
        assert "filtered" in out.lower()
        assert "24" in out

    def test_non_verbose_omits_filtered_detail_line(self, capsys):
        print_host_report(self._make_host(), verbose=False, use_color=False)
        out = capsys.readouterr().out
        assert "no response / firewalled" not in out

    def test_no_open_ports_message(self, capsys):
        host = HostResult(target="x", ip="1.2.3.4", ports=[
            PortResult(host="x", port=80, state="closed", service="HTTP"),
        ])
        print_host_report(host, verbose=False, use_color=False)
        out = capsys.readouterr().out
        assert "No open ports found." in out


class TestExportJson:
    def test_schema_and_values(self):
        hosts = [
            HostResult(target="a.com", ip="1.1.1.1", ports=[
                PortResult(host="a.com", port=80, state="open", service="HTTP"),
                PortResult(host="a.com", port=81, state="closed", service="unknown"),
            ]),
        ]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            export_json(hosts, resolution_errors=["bad-host.invalid: nope"],
                        elapsed=1.234, filename=path)
            with open(path) as f:
                data = json.load(f)

        assert data["hosts_scanned"] == 1
        assert data["duration_seconds"] == 1.234
        assert data["resolution_errors"] == ["bad-host.invalid: nope"]
        assert data["results"][0]["target"] == "a.com"
        assert data["results"][0]["open_ports"] == 1
        assert len(data["results"][0]["ports"]) == 2


class TestPrintFinalSummary:
    def test_reports_resolution_errors(self, capsys):
        hosts = [HostResult(target="a.com", ip="1.1.1.1", ports=[])]
        print_final_summary(hosts, resolution_errors=["oops: bad-host"], elapsed=1.0)
        out = capsys.readouterr().out
        assert "could not be resolved" in out
        assert "oops: bad-host" in out

    def test_no_errors_section_when_clean(self, capsys):
        hosts = [HostResult(target="a.com", ip="1.1.1.1", ports=[])]
        print_final_summary(hosts, resolution_errors=[], elapsed=1.0)
        out = capsys.readouterr().out
        assert "could not be resolved" not in out
