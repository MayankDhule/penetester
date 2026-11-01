"""Unit tests for PentestFramework"""
import unittest
from unittest.mock import Mock, patch, MagicMock
from core.framework import PentestFramework


def make_framework(target='https://example.com'):
    logger = Mock()
    fw = PentestFramework(target=target, logger=logger)
    return fw, logger


class TestPentestFrameworkInit(unittest.TestCase):

    def test_default_async_is_false(self):
        fw, _ = make_framework()
        self.assertFalse(fw.use_async)

    def test_default_max_concurrent(self):
        fw, _ = make_framework()
        self.assertEqual(fw.max_concurrent, 50)

    def test_results_initialized_with_target(self):
        fw, _ = make_framework(target='https://example.com')
        self.assertEqual(fw.results['target'], 'https://example.com')

    def test_results_keys_present(self):
        fw, _ = make_framework()
        for key in ['target', 'profile', 'strategy', 'reconnaissance', 'scanning', 'vulnerabilities', 'exploits']:
            self.assertIn(key, fw.results)


class TestAsyncFlagWiring(unittest.TestCase):

    def test_async_scanner_called_when_use_async_true(self):
        """When use_async=True, _run_scanning should use AsyncScanner"""
        fw, _ = make_framework()
        fw.use_async = True
        fw.profile = {'attack_surface': ['web'], 'open_ports': [443]}
        fw.strategy = {}

        mock_scanner_instance = Mock()
        mock_scanner_instance.execute = Mock(return_value={})

        # AsyncScanner is imported locally inside _run_scanning, patch at source module
        with patch('core.async_scanner.AsyncScanner', return_value=mock_scanner_instance):
            with patch('asyncio.run', return_value={}):
                fw._run_scanning()
        # Verifying asyncio.run was called (meaning the async path was taken)
        # The key check: ScanningEngine should NOT have been called
        # We test this indirectly by patching ScanningEngine and checking it wasn't used
        fw2, _ = make_framework()
        fw2.use_async = True
        fw2.profile = {'attack_surface': ['web'], 'open_ports': [443]}
        fw2.strategy = {}

        with patch('core.framework.ScanningEngine') as mock_sync:
            with patch('core.async_scanner.AsyncScanner', return_value=mock_scanner_instance):
                with patch('asyncio.run', return_value={}):
                    fw2._run_scanning()
            mock_sync.assert_not_called()

    @patch('core.framework.ScanningEngine')
    def test_sync_scanner_called_when_use_async_false(self, mock_sync_scanner):
        """When use_async=False, _run_scanning should use ScanningEngine"""
        fw, _ = make_framework()
        fw.use_async = False
        fw.profile = {'attack_surface': ['web'], 'open_ports': [443]}
        fw.strategy = {}

        mock_scanner_instance = Mock()
        mock_scanner_instance.execute = Mock(return_value={})
        mock_sync_scanner.return_value = mock_scanner_instance

        fw._run_scanning()
        mock_sync_scanner.assert_called_once()


class TestScanResultsPassedToExploiter(unittest.TestCase):

    @patch('core.framework.ExploitationEngine')
    def test_scan_results_passed_to_exploiter(self, mock_exploiter_class):
        """Forms from Phase 2 must be passed to Phase 4 exploiter"""
        fw, _ = make_framework()
        fw.profile = {'attack_surface': ['web']}
        fw.results['scanning'] = {
            'forms': [{'action': 'https://example.com/login', 'method': 'POST', 'inputs': ['user']}],
            'discovered_urls': [],
            'directories': []
        }
        fw.results['vulnerabilities'] = {}

        mock_instance = Mock()
        mock_instance.execute = Mock(return_value={
            'exploits_attempted': 0, 'exploits_successful': 0,
            'exploits': [], 'severity_breakdown': {}
        })
        mock_exploiter_class.return_value = mock_instance

        fw._run_exploitation()

        # Verify ExploitationEngine was called with scan_results
        call_kwargs = mock_exploiter_class.call_args[1]
        self.assertIn('scan_results', call_kwargs)
        self.assertEqual(
            call_kwargs['scan_results']['forms'][0]['action'],
            'https://example.com/login'
        )


class TestGenerateReport(unittest.TestCase):

    def test_report_prints_target(self):
        fw, logger = make_framework(target='https://example.com')
        results = {
            'target': 'https://example.com',
            'profile': None,
            'strategy': None,
            'reconnaissance': None,
            'scanning': None,
            'vulnerabilities': None,
            'exploits': None
        }
        fw.generate_report(results)
        # Logger should have been called with target info
        logger.info.assert_called()

    def test_report_handles_empty_results_gracefully(self):
        fw, logger = make_framework()
        # Should not raise even with all None values
        try:
            fw.generate_report({
                'target': 'https://example.com',
                'profile': None,
                'strategy': None,
                'reconnaissance': None,
                'scanning': None,
                'vulnerabilities': None,
                'exploits': None
            })
        except Exception as e:
            self.fail(f"generate_report raised unexpectedly: {e}")


if __name__ == '__main__':
    unittest.main()
