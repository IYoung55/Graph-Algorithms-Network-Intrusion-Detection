"""Data ingestion, graph construction and explainable heuristic alerts.

This is a demonstration, NOT a production intrusion detection system.
"""
from pathlib import Path
import ipaddress
import pandas as pd
import networkx as nx

REQUIRED = ("timestamp", "src_ip", "dst_ip", "protocol", "bytes", "dst_port")

def load_flows(path):
    df = pd.read_csv(path)
    missing = sorted(set(REQUIRED) - set(df.columns))
    if missing:
        raise ValueError(f"Missing required CSV columns: {', '.join(missing)}")
    if df.empty:
        raise ValueError("CSV has no traffic records")
    for name in ("src_ip", "dst_ip"):
        if df[name].isna().any():
            raise ValueError(f"Missing values in {name}")
        for value in df[name].astype(str):
            try:
                ipaddress.ip_address(value)
            except ValueError as e:
                raise ValueError(f"Invalid IP address in {name}: {value}") from e
    for name in ("bytes", "dst_port"):
        df[name] = pd.to_numeric(df[name], errors="raise")
        if df[name].isna().any() or (df[name] < 0).any():
            raise ValueError(f"Invalid nonnegative value in {name}")
    if (df["dst_port"] > 65535).any() or (df["dst_port"] % 1 != 0).any():
        raise ValueError("Destination port must be an integer between 0 and 65535")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="raise", utc=True)
    if df["protocol"].isna().any():
        raise ValueError("Missing protocol value")
    return df

def build_graph(flows):
    graph = nx.DiGraph()
    for row in flows.itertuples(index=False):
        src, dst = str(row.src_ip), str(row.dst_ip)
        if graph.has_edge(src, dst):
            graph[src][dst]["flow_count"] += 1
            graph[src][dst]["total_bytes"] += int(row.bytes)
        else:
            graph.add_edge(src, dst, flow_count=1, total_bytes=int(row.bytes))
    return graph

def node_metrics(graph):
    centrality = nx.degree_centrality(graph)
    return pd.DataFrame([{
        "ip": n,
        "in_degree": graph.in_degree(n),
        "out_degree": graph.out_degree(n),
        "degree_centrality": round(centrality[n], 5),
    } for n in graph.nodes()]).sort_values(["degree_centrality", "ip"], ascending=[False, True]).reset_index(drop=True)

def detect_anomalies(flows, unique_destination_threshold=5, unique_port_threshold=6):
    """Illustrative heuristics, not learned classification or confirmed attacks.

    One alert per source, if its unique destinations or unique destination ports
    meet the configurable threshold within the entire imported CSV.
    """
    if unique_destination_threshold < 1 or unique_port_threshold < 1:
        raise ValueError("Thresholds must be positive integers")
    grouped = flows.groupby("src_ip").agg(
        unique_destinations=("dst_ip", "nunique"),
        unique_ports=("dst_port", "nunique"),
        flow_count=("dst_ip", "size"),
    ).reset_index()
    flagged = grouped[(grouped.unique_destinations >= unique_destination_threshold) |
                      (grouped.unique_ports >= unique_port_threshold)].copy()
    def reason(row):
        reasons = []
        if row.unique_destinations >= unique_destination_threshold:
            reasons.append(f"{row.unique_destinations} distinct destinations")
        if row.unique_ports >= unique_port_threshold:
            reasons.append(f"{row.unique_ports} distinct destination ports")
        return "; ".join(reasons)
    flagged["reason"] = flagged.apply(reason, axis=1)
    flagged["classification"] = "REVIEW_REQUIRED"
    return flagged.sort_values("src_ip").reset_index(drop=True)
