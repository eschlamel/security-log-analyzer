import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from analyze_logs import detect_failed_login_bursts


class TestDetection(unittest.TestCase):
    def test_detects_five_failures(self):
        events = [{'timestamp': f'2026-11-11T09:00:{i:02d}', 'source_ip': '203.0.113.7', 'status': 'failure'} for i in range(5)]
        self.assertEqual(len(detect_failed_login_bursts(events)), 1)

    def test_ignores_successes(self):
        events = [{'timestamp': f'2026-11-11T09:00:{i:02d}', 'source_ip': '203.0.113.7', 'status': 'success'} for i in range(5)]
        self.assertEqual(detect_failed_login_bursts(events), [])


if __name__ == '__main__':
    unittest.main()
