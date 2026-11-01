"""Unit tests for VulnerabilityDetector concurrency + probe behavior"""
import unittest
from unittest.mock import Mock, patch
import requests
from core.vulnerability_detector import VulnerabilityDetector


def fake_response(status, body: bytes, headers=None):
    r = Mock()
    r.status_code = status
    r.content = body
    r.text = body.decode('utf-8', 'ignore')
    r.headers = headers or {'Content-Type': 'text/html'}
    r.cookies = []
    return r


BASE_BODY = b"<html><body>home page</body></html>"
LOGIN_BODY = (b"<html><body><form method='post'>"
              b"<input name='username'><input type='password' name='pw'>"
              b"</form></body></html>")
NOT_FOUND = fake_response(404, b"<html><body>not found here</body></html>")


def make_detector(dispatch):
    """Build a detector with requests.get patched by a url dispatch fn."""
    with patch('core.vulnerability_detector.requests.get', side_effect=dispatch):
        vd = VulnerabilityDetector('http://t.test', Mock(),
                                   profile={'attack_surface': ['web']}, scan_results={})
    return vd


class TestProbeUrls(unittest.TestCase):

    def test_maps_responses_and_none_on_failure(self):
        ok = fake_response(200, b"ok")

        def dispatch(url, **kw):
            if url.endswith('/good'):
                return ok
            raise requests.ConnectionError("boom")

        vd = make_detector(lambda url, **kw: fake_response(200, BASE_BODY))
        with patch('core.vulnerability_detector.requests.get', side_effect=dispatch):
            res = vd._probe_urls(['http://t.test/good', 'http://t.test/bad'])
        self.assertIs(res['http://t.test/good'], ok)
        self.assertIsNone(res['http://t.test/bad'])

    def test_empty_urls_returns_empty(self):
        vd = make_detector(lambda url, **kw: fake_response(200, BASE_BODY))
        self.assertEqual(vd._probe_urls([]), {})


class TestAuthCheckConcurrentPath(unittest.TestCase):

    def test_login_form_without_csrf_detected(self):
        def dispatch(url, **kw):
            if url.endswith('/login'):
                return fake_response(200, LOGIN_BODY)
            if url.rstrip('/') == 'http://t.test':
                return fake_response(200, BASE_BODY)
            return NOT_FOUND

        vd = make_detector(dispatch)
        with patch('core.vulnerability_detector.requests.get', side_effect=dispatch):
            vd.check_authentication_issues('http://t.test')

        titles = [v['title'] for v in vd.vulnerabilities]
        self.assertTrue(any('CSRF' in t for t in titles),
                        msg=f"expected a CSRF finding, got {titles}")


if __name__ == '__main__':
    unittest.main()
