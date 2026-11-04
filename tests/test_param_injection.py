"""Tests for discovered-parameter injection testing in the exploiter"""
import unittest
from unittest.mock import Mock, patch
import requests
from core.exploiter import ExploitationEngine


def make_engine(scan_results):
    return ExploitationEngine(
        target='http://shop.test',
        logger=Mock(),
        profile={'attack_surface': ['web']},
        vulnerabilities={},
        scan_results=scan_results,
    )


def resp(status=200, text=''):
    r = Mock()
    r.status_code = status
    r.text = text
    return r


class TestParameterizedTargets(unittest.TestCase):

    def test_extracts_params_from_discovered_urls(self):
        eng = make_engine({'discovered_urls': [
            'http://shop.test/listproducts.php?cat=1',
            'http://shop.test/artists.php?artist=2&x=9',
            'http://shop.test/about.php',           # no query -> ignored
            'http://shop.test/listproducts.php?cat=5',  # dup base+params -> deduped
        ]})
        targets = eng._parameterized_targets()
        bases = sorted(b for b, _ in targets)
        self.assertEqual(bases, ['http://shop.test/artists.php',
                                 'http://shop.test/listproducts.php'])
        params = dict((b, p) for b, p in targets)
        self.assertEqual(set(params['http://shop.test/artists.php']), {'artist', 'x'})


class TestParamSqli(unittest.TestCase):

    def test_error_based_detected_on_param(self):
        eng = make_engine({'discovered_urls': ['http://shop.test/p.php?cat=1']})

        def dispatch(url, params=None, **kw):
            params = params or {}
            val = str(params.get('cat', ''))
            # baseline (cat=1) is clean; injected value triggers an SQL error
            if val == '1':
                return resp(200, '<html>products listing</html>')
            return resp(200, "<html>You have an error in your SQL syntax</html>")

        with patch('core.exploiter.requests.get', side_effect=dispatch):
            found = eng._test_params_sqli(eng._parameterized_targets())
        self.assertTrue(found)
        self.assertEqual(found[0]['confidence'], 'probable')
        self.assertIn('cat', found[0]['payload'])


class TestParamXss(unittest.TestCase):

    def test_reflection_detected(self):
        eng = make_engine({'discovered_urls': ['http://shop.test/s.php?q=hello']})

        def dispatch(url, params=None, **kw):
            params = params or {}
            return resp(200, '<html>results for ' + str(params.get('q', '')) + '</html>')

        with patch('core.exploiter.requests.get', side_effect=dispatch):
            found = eng._test_params_xss(eng._parameterized_targets())
        self.assertTrue(found)
        self.assertIn('XSS', found[0]['type'])
        self.assertEqual(found[0]['confidence'], 'probable')

    def test_no_reflection_no_finding(self):
        eng = make_engine({'discovered_urls': ['http://shop.test/s.php?q=hello']})

        def dispatch(url, params=None, **kw):
            return resp(200, '<html>safe, encoded output</html>')

        with patch('core.exploiter.requests.get', side_effect=dispatch):
            found = eng._test_params_xss(eng._parameterized_targets())
        self.assertEqual(found, [])


if __name__ == '__main__':
    unittest.main()
