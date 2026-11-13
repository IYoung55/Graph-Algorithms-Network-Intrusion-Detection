"""Run with python -m graph_ids --input data/sample_flows.csv"""
import argparse
from pathlib import Path
from . import __version__
from .core import load_flows, build_graph, node_metrics, detect_anomalies
from .visualize import save_graph

def main():
    parser = argparse.ArgumentParser(description="Graph IDS milestone 1 demonstration")
    parser.add_argument("--input", default="data/sample_flows.csv", help="CSV network flows")
    parser.add_argument("--output", default="outputs", help="Output directory")
    parser.add_argument("--destination-threshold", type=int, default=5)
    parser.add_argument("--port-threshold", type=int, default=6)
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    flows = load_flows(args.input)
    graph = build_graph(flows)
    metrics = node_metrics(graph)
    alerts = detect_anomalies(flows, args.destination_threshold, args.port_threshold)
    metrics.to_csv(output / "node_metrics.csv", index=False)
    alerts.to_csv(output / "review_alerts.csv", index=False)
    save_graph(graph, set(alerts.src_ip), output / "network_graph.png")
    print(f"Graph IDS v{__version__} | flows={len(flows)} | nodes={graph.number_of_nodes()} | edges={graph.number_of_edges()}")
    print(f"Heuristic review flags: {len(alerts)} (not confirmed attacks)")
    print(f"Saved: {output / 'network_graph.png'}, node_metrics.csv, review_alerts.csv")

if __name__ == "__main__":
    main()
