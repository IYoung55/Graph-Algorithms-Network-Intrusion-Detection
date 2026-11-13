import unittest
import tempfile
from pathlib import Path
import pandas as pd
from graph_ids.core import load_flows, build_graph, node_metrics, detect_anomalies

class TestGraphIDS(unittest.TestCase):
    def setUp(self):
        self.df = pd.DataFrame([
            {"timestamp":"2026-11-01T12:00:00Z", "src_ip":"10.0.0.1", "dst_ip":f"10.0.0.{i}", "protocol":"TCP", "bytes":100, "dst_port":80+i}
            for i in range(2,8)
        ])
    def test_graph_nodes_edges(self):
        graph = build_graph(self.df)
        self.assertEqual(graph.number_of_nodes(), 7)
        self.assertEqual(graph.number_of_edges(), 6)
    def test_centrality(self):
        metrics = node_metrics(build_graph(self.df))
        self.assertEqual(metrics.iloc[0]["ip"], "10.0.0.1")
    def test_heuristic_flags(self):
        alerts = detect_anomalies(self.df)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts.iloc[0]["classification"], "REVIEW_REQUIRED")
    def test_high_threshold_no_flags(self):
        self.assertTrue(detect_anomalies(self.df, 10, 10).empty)
    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_anomalies(self.df, 0, 1)
    def test_load_validation(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "flows.csv"
            self.df.to_csv(path, index=False)
            self.assertEqual(len(load_flows(path)), 6)
            self.df.drop(columns=["src_ip"]).to_csv(path, index=False)
            with self.assertRaises(ValueError):
                load_flows(path)

if __name__ == "__main__":
    unittest.main()
