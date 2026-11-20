"""Headless-friendly graph rendering."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

def save_graph(graph, alert_ips, output):
    fig, ax = plt.subplots(figsize=(12, 8))
    positions = nx.spring_layout(graph, seed=42)
    colors = ["#d65c52" if n in set(alert_ips) else "#4b89b9" for n in graph.nodes]
    nx.draw_networkx(graph, pos=positions, ax=ax, node_color=colors,
                     node_size=1000, font_size=7, arrows=True, arrowsize=12,
                     edge_color="#aab3bb", width=1.2)
    ax.set_title("Network communication graph | red = heuristic review flag")
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches="tight")
    plt.close(fig)
