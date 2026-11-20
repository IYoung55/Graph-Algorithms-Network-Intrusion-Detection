import unittest
import pandas as pd
from graph_ids.core import analyze_windows

class WindowTests(unittest.TestCase):
    def setUp(self):
        self.flows = pd.DataFrame([
            {"timestamp": "2026-11-01T12:00:00Z", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80, "bytes": 100},
            *[{"timestamp": "2026-11-01T12:06:00Z", "src_ip": "10.0.0.1", "dst_ip": f"10.0.0.{i}", "dst_port": 80+i, "bytes": 100} for i in range(2,8)]
        ])
    def test_two_windows_and_alert(self):
        result = analyze_windows(self.flows)
        self.assertEqual(len(result), 2)
        self.assertEqual(result.iloc[1]["classification"], "REVIEW_REQUIRED")
        self.assertEqual(result.iloc[0]["classification"], "NO_FLAG")
    def test_no_false_baseline_with_single_window(self):
        result = analyze_windows(self.flows.iloc[:1])
        self.assertEqual(result.iloc[0]["classification"], "NO_FLAG")
    def test_invalid_parameters(self):
        with self.assertRaises(ValueError): analyze_windows(self.flows, window_minutes=0)
        with self.assertRaises(ValueError): analyze_windows(self.flows, baseline_multiplier=1)
    def test_window_boundary(self):
        result = analyze_windows(self.flows, window_minutes=10)
        self.assertEqual(len(result), 1)
if __name__ == "__main__": unittest.main()
