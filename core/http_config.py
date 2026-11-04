"""
Global HTTP policy for Pentestrr.

Applies a request throttle (rate limit) across the whole tool without editing
individual call sites, by wrapping requests.get/head/post. The throttle is a
shared token spaced by `delay` seconds, so it holds even when requests are
issued concurrently from the thread pools used in scanning/detection.

This is a politeness / safety control: it reduces load on the target and makes
it less likely the scan trips rate limiting or gets the source IP blocked.
"""
import threading
import time
import functools
import requests

_lock = threading.Lock()
_state = {'delay': 0.0, 'last': 0.0}
_installed = False
_originals = {}


def _throttle():
    """Block until at least `delay` seconds have passed since the last request."""
    delay = _state['delay']
    if delay <= 0:
        return
    with _lock:
        now = time.monotonic()
        wait = _state['last'] + delay - now
        if wait > 0:
            time.sleep(wait)
            now = time.monotonic()
        _state['last'] = now


def _install():
    global _installed
    if _installed:
        return
    for name in ('get', 'head', 'post'):
        original = getattr(requests, name)
        _originals[name] = original

        @functools.wraps(original)
        def wrapper(*args, _original=original, **kwargs):
            _throttle()
            return _original(*args, **kwargs)

        setattr(requests, name, wrapper)
    _installed = True


def configure(delay: float = 0.0):
    """Enable a global inter-request delay (seconds). 0 disables throttling."""
    _state['delay'] = max(0.0, float(delay))
    if _state['delay'] > 0:
        _install()


def reset():
    """Restore original requests functions (used by tests)."""
    global _installed
    for name, original in _originals.items():
        setattr(requests, name, original)
    _originals.clear()
    _state['delay'] = 0.0
    _state['last'] = 0.0
    _installed = False
