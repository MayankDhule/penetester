"""Tests for the concurrent port scans in profiler and reconnaissance"""
import unittest
from unittest.mock import Mock, patch
from core.profiler import SmartProfiler
from core.reconnaissance import ReconnaissanceEngine


def _socket_mock_with_open(open_ports):
    """Return a mock socket class whose connect_ex returns 0 for open_ports."""
    inst = Mock()
    inst.connect_ex.side_effect = lambda addr: 0 if addr[1] in open_ports else 1
    inst.settimeout.return_value = None
    inst.close.return_value = None
    cls = Mock(return_value=inst)
    return cls


class TestProfilerPortScan(unittest.TestCase):

    @patch('core.profiler.socket.gethostbyname', return_value='1.2.3.4')
    def test_only_open_ports_recorded(self, _resolve):
        with patch('core.profiler.socket.socket', _socket_mock_with_open({80, 443})):
            p = SmartProfiler('example.com', Mock())
            p._quick_port_check()
        self.assertIn(80, p.profile['open_ports'])
        self.assertIn(443, p.profile['open_ports'])
        self.assertNotIn(22, p.profile['open_ports'])
        # Result is sorted ascending
        self.assertEqual(p.profile['open_ports'], sorted(p.profile['open_ports']))


class TestReconPortScan(unittest.TestCase):

    def test_only_open_ports_recorded(self):
        recon = ReconnaissanceEngine('example.com', Mock())
        recon.results['ip_addresses'] = ['1.2.3.4']
        with patch('core.reconnaissance.socket.socket', _socket_mock_with_open({22, 8080})):
            recon.quick_port_scan()
        self.assertEqual(recon.results['open_ports'], [22, 8080])

    def test_no_ip_returns_without_error(self):
        recon = ReconnaissanceEngine('example.com', Mock())
        recon.results['ip_addresses'] = []
        recon.quick_port_scan()  # should early-return, no exception
        self.assertEqual(recon.results['open_ports'], [])


if __name__ == '__main__':
    unittest.main()
