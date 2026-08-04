"""
The core async scanning engine.

Design notes
------------
- Uses asyncio.open_connection() + asyncio.wait_for() rather than raw
  sockets/threads. This lets a single event loop juggle thousands of
  in-flight connection attempts far more cheaply than an equivalent
  number of OS threads would.
- Classification and banner-grabbing are two *separate* connections
  for ports that need TLS. Trying to "upgrade" an already-open plain
  connection to TLS mid-stream is possible via low-level asyncio APIs
  but fragile; opening a second, purpose-built connection when a
  banner is actually requested is simpler and more robust.
- Concurrency is capped with an asyncio.Semaphore so a large scan
  can't try to open tens of thousands of sockets simultaneously.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from typing import Callable

from .models import HostResult, PortResult
from .ports import HTTP_PORTS, HTTPS_PORTS, service_name

ProgressCallback = Callable[[int, int], None]


async def resolve_target(target: str) -> str:
    """Resolve a hostname or IP literal to a concrete IP address string."""
    try:
        # Already a literal IPv4/IPv6 address -> nothing to resolve.
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        # UnicodeError covers malformed hostnames (e.g. empty labels
        # like "bad..host") that fail IDNA encoding before DNS is even
        # queried.
        raise ValueError(f"Could not resolve host '{target}': {exc}") from exc

    if not infos:
        raise ValueError(f"Could not resolve host '{target}': no address returned")

    return infos[0][4][0]


async def _classify_connection(ip: str, port: int, timeout: float) -> tuple[str, float]:
    """Attempt a bare TCP connect and classify the result. Returns (state, ms)."""
    start = time.perf_counter()
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        return "open", round((time.perf_counter() - start) * 1000, 2)
    except asyncio.TimeoutError:
        # No response at all within the window - usually a firewall
        # silently dropping the packets.
        return "filtered", round((time.perf_counter() - start) * 1000, 2)
    except (ConnectionRefusedError, ConnectionResetError):
        # The host actively refused / reset the connection.
        return "closed", round((time.perf_counter() - start) * 1000, 2)
    except OSError:
        # Anything else (network unreachable, no route to host, etc.)
        # is treated as filtered/unreachable rather than a clean
        # refusal.
        return "filtered", round((time.perf_counter() - start) * 1000, 2)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def _grab_banner(ip: str, port: int, timeout: float) -> str | None:
    """
    Attempt to read a service banner on an open port.

    HTTPS ports get a fresh TLS-wrapped connection (self-signed/
    unverifiable certs are tolerated — the goal is reconnaissance, not
    certificate validation). HTTP ports get a minimal HEAD probe since
    many web servers won't speak first. Everything else is a passive
    read, for services that greet on connect (SSH, FTP, SMTP, ...).
    """
    writer = None
    try:
        if port in HTTPS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )

        if port in HTTP_PORTS or port in HTTPS_PORTS:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        if not data:
            return None
        banner = data.decode(errors="replace").strip().replace("\r\n", " | ")
        return banner[:150]  # keep output readable
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def probe_port(
    ip: str,
    port: int,
    *,
    timeout: float,
    grab_banners: bool,
    retry_filtered: bool,
    host_label: str,
) -> PortResult:
    """
    Probe a single port, with an optional single retry on a filtered
    result. Concurrency is bounded by the caller (a fixed-size worker
    pool in scan_hosts), not by this function.
    """
    state, elapsed_ms = await _classify_connection(ip, port, timeout)

    if state == "filtered" and retry_filtered:
        # A dropped probe can just be transient jitter rather than a
        # real firewall rule. One quick retry meaningfully cuts down
        # false "filtered" classifications without doubling scan time
        # overall (only filtered ports pay the retry cost).
        await asyncio.sleep(0.05)
        retry_state, retry_ms = await _classify_connection(ip, port, timeout)
        if retry_state != "filtered":
            state, elapsed_ms = retry_state, retry_ms

    banner = None
    if state == "open" and grab_banners:
        banner = await _grab_banner(ip, port, timeout)

    return PortResult(
        host=host_label,
        port=port,
        state=state,
        service=service_name(port),
        banner=banner,
        response_ms=elapsed_ms,
    )


async def scan_hosts(
    targets: list[str],
    port_list: list[int],
    *,
    timeout: float = 1.0,
    concurrency: int = 200,
    grab_banners: bool = False,
    retry_filtered: bool = True,
    progress_cb: ProgressCallback | None = None,
) -> tuple[list[HostResult], list[str]]:
    """
    Resolve every target and scan all host x port combinations using a
    fixed-size pool of worker coroutines pulling from a shared queue.

    This deliberately avoids creating one asyncio.Task per port. With
    tens of thousands of ports, that would mean tens of thousands of
    live Task objects managed by the event loop at once -- real
    overhead, even with a semaphore gating actual connections. A small,
    fixed pool of workers draining a queue mirrors how a
    ThreadPoolExecutor stays cheap regardless of how much work is
    queued behind it.

    Returns (host_results, resolution_errors). A target that fails to
    resolve does not abort the whole scan -- it's reported separately
    so the rest of the targets still get scanned.
    """
    resolved: list[tuple[str, str]] = []
    resolution_errors: list[str] = []

    for t in targets:
        try:
            ip = await resolve_target(t)
            resolved.append((t, ip))
        except ValueError as exc:
            resolution_errors.append(str(exc))

    if not resolved:
        return [], resolution_errors

    host_results: dict[str, HostResult] = {
        label: HostResult(target=label, ip=ip) for label, ip in resolved
    }

    queue: asyncio.Queue[tuple[str, str, int]] = asyncio.Queue()
    for label, ip in resolved:
        for port in port_list:
            queue.put_nowait((label, ip, port))

    total = queue.qsize()
    completed = 0

    async def _worker() -> None:
        nonlocal completed
        while True:
            try:
                label, ip, port = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            result = await probe_port(
                ip, port,
                timeout=timeout,
                grab_banners=grab_banners,
                retry_filtered=retry_filtered,
                host_label=label,
            )
            host_results[label].ports.append(result)
            # No lock needed: asyncio is single-threaded/cooperative,
            # so this increment can't be interleaved by another
            # coroutine mid-statement the way it could across threads.
            completed += 1
            if progress_cb:
                progress_cb(completed, total)

    num_workers = min(concurrency, total) if total else 0
    workers = [asyncio.create_task(_worker()) for _ in range(num_workers)]
    if workers:
        await asyncio.gather(*workers)

    for hr in host_results.values():
        hr.ports.sort(key=lambda r: r.port)

    return list(host_results.values()), resolution_errors
