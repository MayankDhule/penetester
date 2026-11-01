"""Unit tests for SmartProfiler"""
import unittest
from unittest.mock import Mock, patch, MagicMock
from core.profiler import SmartProfiler


class TestSmartProfiler(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.profiler = SmartProfiler("example.com", self.logger)

    # --- IP detection ---

    def test_is_ip_address_true(self):
        self.assertTrue(self.profiler._is_ip_address("192.168.1.1"))

    def test_is_ip_address_false_for_domain(self):
        self.assertFalse(self.profiler._is_ip_address("example.com"))

    def test_is_ip_address_false_for_url(self):
        self.assertFalse(self.profiler._is_ip_address("https://example.com"))

    # --- Profile structure ---

    def test_profile_initialized_with_target(self):
        self.assertEqual(self.profiler.profile['target'], 'example.com')

    def test_profile_attack_surface_is_list(self):
        self.assertIsInstance(self.profiler.profile.get('attack_surface', []), list)

    def test_profile_open_ports_is_list(self):
        self.assertIsInstance(self.profiler.profile.get('open_ports', []), list)

    # --- Strategy structure ---

    def test_build_strategy_returns_dict(self):
        """build_strategy populates self.strategy with required keys"""
        self.profiler.profile['attack_surface'] = ['web']
        self.profiler.profile['open_ports'] = [443]
        self.profiler.profile['ssl_enabled'] = True
        self.profiler.profile['cms'] = None
        self.profiler.profile['target_type'] = 'domain'
        self.profiler.profile['api_detected'] = False
        self.profiler.build_strategy()
        self.assertIsInstance(self.profiler.strategy, dict)

    def test_build_strategy_has_risk_level(self):
        self.profiler.profile['attack_surface'] = ['web']
        self.profiler.profile['open_ports'] = [443]
        self.profiler.profile['ssl_enabled'] = True
        self.profiler.profile['cms'] = None
        self.profiler.profile['target_type'] = 'domain'
        self.profiler.profile['api_detected'] = False
        self.profiler.build_strategy()
        self.assertIn('risk_level', self.profiler.strategy)

    def test_build_strategy_has_recommended_phases(self):
        self.profiler.profile['attack_surface'] = ['web']
        self.profiler.profile['open_ports'] = [443]
        self.profiler.profile['ssl_enabled'] = True
        self.profiler.profile['cms'] = None
        self.profiler.profile['target_type'] = 'domain'
        self.profiler.profile['api_detected'] = False
        self.profiler.build_strategy()
        self.assertIn('recommended_phases', self.profiler.strategy)

    def test_build_strategy_has_estimated_time(self):
        self.profiler.profile['attack_surface'] = ['web']
        self.profiler.profile['open_ports'] = [443]
        self.profiler.profile['ssl_enabled'] = True
        self.profiler.profile['cms'] = None
        self.profiler.profile['target_type'] = 'domain'
        self.profiler.profile['api_detected'] = False
        self.profiler.build_strategy()
        self.assertIn('estimated_time', self.profiler.strategy)

    def test_risk_level_is_valid_value(self):
        self.profiler.profile['attack_surface'] = ['web']
        self.profiler.profile['open_ports'] = [443]
        self.profiler.profile['ssl_enabled'] = True
        self.profiler.profile['cms'] = None
        self.profiler.profile['target_type'] = 'domain'
        self.profiler.profile['api_detected'] = False
        self.profiler.build_strategy()
        self.assertIn(self.profiler.strategy['risk_level'], ['low', 'medium', 'high', 'critical'])

    def test_estimated_time_is_positive(self):
        self.profiler.profile['attack_surface'] = ['web']
        self.profiler.profile['open_ports'] = [80, 443]
        self.profiler.profile['ssl_enabled'] = True
        self.profiler.profile['cms'] = 'WordPress'
        self.profiler.profile['target_type'] = 'domain'
        self.profiler.profile['api_detected'] = False
        self.profiler.build_strategy()
        self.assertGreater(self.profiler.strategy['estimated_time'], 0)


class TestSmartProfilerNetworkMocked(unittest.TestCase):
    """Tests that mock HTTP calls"""

    def setUp(self):
        self.logger = Mock()

    @patch('core.profiler.requests.get')
    def test_ssl_detection_sets_port_443(self, mock_get):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Server': 'nginx', 'Content-Type': 'text/html', 'X-Powered-By': ''}
        mock_resp.text = '<html><head></head><body></body></html>'
        mock_resp.url = 'https://example.com'
        mock_resp.cookies = {}
        mock_get.return_value = mock_resp

        profiler = SmartProfiler("example.com", self.logger)
        profiler._try_web_service()
        self.assertIn(443, profiler.profile.get('open_ports', []))

    @patch('core.profiler.requests.get')
    def test_wordpress_cms_detection(self, mock_get):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Server': 'Apache', 'X-Powered-By': 'PHP/8.1', 'Content-Type': 'text/html'}
        mock_resp.text = '<html><link rel="stylesheet" href="/wp-content/themes/theme/style.css"></html>'
        mock_resp.url = 'https://example.com'
        mock_resp.cookies = {}
        mock_get.return_value = mock_resp

        profiler = SmartProfiler("example.com", self.logger)
        cms = profiler._detect_cms(mock_resp)
        self.assertEqual(cms, 'WordPress')


class TestCMSDetection(unittest.TestCase):

    def setUp(self):
        self.logger = Mock()
        self.profiler = SmartProfiler("example.com", self.logger)

    def _make_response(self, text, headers=None):
        resp = Mock()
        resp.text = text
        resp.headers = headers or {}
        return resp

    def test_detects_wordpress(self):
        resp = self._make_response('<html><script src="/wp-includes/js/jquery.js"></script></html>')
        self.assertEqual(self.profiler._detect_cms(resp), 'WordPress')

    def test_detects_joomla(self):
        resp = self._make_response('<html><!-- Joomla! - Open Source Content Management --></html>')
        self.assertEqual(self.profiler._detect_cms(resp), 'Joomla')

    def test_returns_none_for_unknown(self):
        resp = self._make_response('<html><body>Plain site</body></html>')
        self.assertIsNone(self.profiler._detect_cms(resp))


if __name__ == '__main__':
    unittest.main()
