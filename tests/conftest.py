"""Shared pytest fixtures."""

from __future__ import annotations

import asyncio

import pytest


@pytest.fixture
async def local_server():
    """
    Spin up a real asyncio TCP server on 127.0.0.1 with a dynamically
    assigned free port. Tests connect to it to exercise the scanner's
    actual networking code path (no mocking of sockets), giving
    genuine end-to-end confidence rather than just testing internal
    logic in isolation.

    Yields (host, port). Optionally sends `banner` to each connection
    if the test sets `server.banner` before connecting.
    """
    state = {"banner": None}

    async def handle(reader, writer):
        if state["banner"]:
            try:
                writer.write(state["banner"])
                await writer.drain()
            except OSError:
                pass
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]

    class Handle:
        def __init__(self):
            self.host = host
            self.port = port

        def set_banner(self, data: bytes) -> None:
            state["banner"] = data

    handle_obj = Handle()

    async with server:
        yield handle_obj


@pytest.fixture
def unused_port():
    """A local port nothing is listening on, for testing 'closed' state.

    Skipped on Windows: there, a connection to an unbound loopback port is not
    refused instantly. It times out and is correctly classified as 'filtered',
    so tests that expect 'closed' only hold on Linux and macOS (see the
    Engineering Notes in the README).
    """
    import socket
    import sys

    if sys.platform == "win32":
        pytest.skip("unbound loopback ports time out (filtered) on Windows, not refused")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # closed immediately -> nothing listens -> connections get refused
    return port
