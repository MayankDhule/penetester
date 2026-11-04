"""Tests for the global request throttle (core.http_config)"""
import time
import unittest
import requests
from core import http_config


class TestThrottle(unittest.TestCase):

    def tearDown(self):
        http_config.reset()

    def test_throttle_spaces_successive_calls(self):
        http_config._state['delay'] = 0.2
        http_config._state['last'] = 0.0
        http_config._throttle()           # first call: no wait, records timestamp
        start = time.monotonic()
        http_config._throttle()           # second call must wait ~0.2s
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.15)

    def test_zero_delay_no_wait(self):
        http_config._state['delay'] = 0.0
        start = time.monotonic()
        http_config._throttle()
        self.assertLess(time.monotonic() - start, 0.05)

    def test_configure_installs_wrapper_and_passthrough(self):
        calls = {'n': 0}
        original_get = requests.get
        try:
            requests.get = lambda *a, **k: calls.__setitem__('n', calls['n'] + 1) or 'stub'
            http_config.configure(delay=0.01)      # wraps the stub
            result = requests.get('http://example.test')
            self.assertEqual(result, 'stub')
            self.assertEqual(calls['n'], 1)
        finally:
            http_config.reset()
            requests.get = original_get


if __name__ == '__main__':
    unittest.main()
