"""Tests for the concurrent probe helper and enumeration in the scanner"""
import unittest
from unittest.mock import Mock, patch
import requests
from core.scanner import ScanningEngine


def resp(status=200, body=b'', headers=None):
    r = Mock()
    r.status_code = status
    r.content = body
    r.text = body.decode('utf-8', 'ignore') if isinstance(body, bytes) else body
    r.headers = headers or {}
    return r


def make_scanner():
    return ScanningEngine('http://t.test', Mock(), profile={}, strategy={})


class TestProbe(unittest.TestCase):

    def test_maps_and_handles_failure(self):
        eng = make_scanner()
        ok = resp(200)

        def dispatch(u, **kw):
            if u.endswith('/good/'):
                return ok
            raise requests.ConnectionError('x')

        with patch('core.scanner.requests.head', side_effect=dispatch):
            r = eng._probe(['http://t.test/good/', 'http://t.test/bad/'], method='head')
        self.assertIs(r['http://t.test/good/'], ok)
        self.assertIsNone(r['http://t.test/bad/'])

    def test_empty(self):
        self.assertEqual(make_scanner()._probe([]), {})


class TestDirectoryDiscovery(unittest.TestCase):

    def test_only_responding_dirs_recorded(self):
        eng = make_scanner()

        def dispatch(u, **kw):
            return resp(200 if '/admin/' in u else 404)

        with patch('core.scanner.requests.head', side_effect=dispatch):
            eng.discover_directories('http://t.test')
        self.assertTrue(any(d.endswith('/admin/') for d in eng.results['directories']))
        self.assertFalse(any(d.endswith('/css/') for d in eng.results['directories']))


if __name__ == '__main__':
    unittest.main()
