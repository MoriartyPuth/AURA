"""Small concurrency helpers for I/O-bound work (HTTP probes, external tools).

All requests still go through AuraSession, so the global request_delay/jitter
pacing in http_utils applies across threads; these helpers only remove the idle
time spent waiting on one response before sending the next.
"""
from concurrent.futures import ThreadPoolExecutor

DEFAULT_HTTP_WORKERS = 8
DEFAULT_TOOL_WORKERS = 2


def _setting(config, key, default):
    try:
        value = int(((config or {}).get("settings") or {}).get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(value, 1)


def http_workers(config):
    """Concurrent HTTP requests a module may have in flight (settings.http_workers)."""
    return _setting(config, "http_workers", DEFAULT_HTTP_WORKERS)


def tool_workers(config):
    """External scanner processes (sqlmap, dalfox, ...) run at once (settings.tool_workers)."""
    return _setting(config, "tool_workers", DEFAULT_TOOL_WORKERS)


def pmap(fn, items, workers):
    """Like list(map(fn, items)) but concurrent; result order matches `items`.

    An exception in `fn` propagates, so callers keep their own try/except inside `fn`.
    """
    items = list(items)
    if not items:
        return []
    if workers <= 1 or len(items) == 1:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        return list(pool.map(fn, items))


def run_parallel(*thunks, workers=None):
    """Run independent zero-arg callables concurrently, returning their results in order."""
    return pmap(lambda f: f(), thunks, workers or len(thunks))
