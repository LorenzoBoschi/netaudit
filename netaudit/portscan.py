"""TCP connect scanner: it opens and closes connections and never sends data to a service.

Lessons built in:
- simultaneous connections have a global cap: above it, open ports get missed (false negatives);
- every port found is re-confirmed with several attempts;
- the scan stops if the workstation changes network halfway through.
"""
from __future__ import annotations

import asyncio
import errno
import time


# errno values that mean "this workstation ran out of sockets/buffers", not "the port is closed"
_LOCAL_EXHAUSTION = {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, 10024, 10055}


def raise_file_limit(wanted: int = 4096) -> None:
    """On Unix the default limit on open files (1024 on Linux, 256 on macOS) is below what a scan
    needs: raise the soft limit as far as the hard limit allows. No-op on Windows."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = wanted if hard == resource.RLIM_INFINITY else min(wanted, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (ImportError, ValueError, OSError):
        pass


async def tcp_open(ip: str, port: int, timeout: float, state: dict | None = None) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except OSError as exc:
        if state is not None and exc.errno in _LOCAL_EXHAUSTION:
            state["local_errors"] = state.get("local_errors", 0) + 1
        return False
    except Exception:
        return False
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except Exception:
        pass
    return True


class ScanResult:
    def __init__(self):
        self.open: dict[str, list[int]] = {}
        self.incomplete: set[str] = set()   # hosts not finished (interruption)
        self.aborted = False
        self.seconds = 0.0
        self.local_errors = 0               # connections lost to local socket exhaustion


async def _scan_host(ip, ports, workers, timeout, state, result, on_progress):
    queue: asyncio.Queue = asyncio.Queue()
    for port in ports:
        queue.put_nowait(port)
    found: list[int] = []
    total = len(ports)
    done = 0
    next_mark = 10

    async def worker():
        nonlocal done, next_mark
        while not state["abort"]:
            try:
                port = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if await tcp_open(ip, port, timeout, state):
                found.append(port)
            done += 1
            if on_progress and total >= 5000:
                pct = done * 100 // total
                if pct >= next_mark:
                    on_progress(ip, min(pct, 100), sorted(found))
                    next_mark += 10

    try:
        await asyncio.gather(*[worker() for _ in range(max(1, min(workers, total)))])
    except asyncio.CancelledError:
        # Ctrl+C: keep what was found so far so a partial report can still be written
        result.open[ip] = sorted(found)
        result.incomplete.add(ip)
        raise
    if state["abort"]:
        result.incomplete.add(ip)
    confirmed = []
    try:
        for port in sorted(found):
            for _attempt in range(3):
                if state["abort"]:
                    break
                if await tcp_open(ip, port, timeout * 2, state):
                    confirmed.append(port)
                    break
                await asyncio.sleep(0.4)
    except asyncio.CancelledError:
        result.open[ip] = sorted(found)      # cancelled while re-confirming: keep the unconfirmed list
        result.incomplete.add(ip)
        raise
    result.open[ip] = confirmed


async def scan(targets: dict[str, list[int]], workers: int, timeout: float, max_sockets: int,
               on_progress=None, should_abort=None, on_batch=None, result: ScanResult | None = None) -> ScanResult:
    """Scan targets = {ip: [ports]} in batches that respect the connection cap.
    Pass your own `result` to keep partial findings if the scan is cancelled."""
    result = result if result is not None else ScanResult()
    state = {"abort": False, "local_errors": 0}
    started = time.time()
    ips = list(targets)

    async def watchdog():
        while True:
            await asyncio.sleep(5)
            try:
                if should_abort():
                    state["abort"] = True
                    return
            except Exception:
                pass

    guard = asyncio.ensure_future(watchdog()) if should_abort else None
    try:
        index = 0
        while index < len(ips) and not state["abort"]:
            if should_abort and should_abort():
                state["abort"] = True
                break
            # the batch grows while the sum of the workers stays under the cap
            batch, sockets = [], 0
            while index < len(ips):
                need = max(1, min(workers, len(targets[ips[index]])))
                if batch and sockets + need > max_sockets:
                    break
                batch.append(ips[index])
                sockets += need
                index += 1
            if on_batch:
                on_batch(batch, index, len(ips))
            await asyncio.gather(*[
                _scan_host(ip, targets[ip], workers, timeout, state, result, on_progress) for ip in batch])
        for ip in ips[index:]:
            result.incomplete.add(ip)
    finally:
        if guard:
            guard.cancel()
        result.local_errors += state["local_errors"]
    result.aborted = state["abort"]
    result.seconds = time.time() - started
    return result


def estimate_seconds(n_hosts: int, n_ports: int, workers: int, timeout: float, max_sockets: int) -> float:
    """Conservative estimate: nearly every port is filtered and expires at the timeout."""
    per_host_workers = max(1, min(workers, n_ports))
    hosts_per_batch = max(1, max_sockets // per_host_workers)
    batches = -(-n_hosts // hosts_per_batch)
    return batches * (n_ports / per_host_workers) * timeout * 1.05
