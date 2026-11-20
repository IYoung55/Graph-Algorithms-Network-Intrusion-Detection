# Suggested screencast script (approximately 2–3 minutes)

**0:00–0:20 — Introduction**
"Hello, this is Ivory Young. This is Milestone 1, version 0.1.0, for my Graph Algorithms for Network Intrusion Detection capstone project."

**0:20–0:50 — Project structure**
Show the repository folders: `src/graph_ids`, `data`, `tests`, `docs`. Explain that the demonstration CSV is synthetic.

**0:50–1:20 — Run application**
Run `python -m graph_ids --input data/sample_flows.csv` after configuring `PYTHONPATH=src`. Show the printed counts and generated files.

**1:20–1:55 — Results**
Open `outputs/network_graph.png`, `outputs/node_metrics.csv`, and `outputs/review_alerts.csv`. Explain nodes, directed edges, centrality, and why red nodes are flagged for review. State that alerts are heuristic, not confirmed attacks.

**1:55–2:20 — Tests**
Run `python -m unittest discover -s tests -v` and show passing tests. Discuss input validation and deterministic graph construction.

**2:20–2:45 — Next steps**
Explain plans for time-window analysis, labeled-data evaluation, and comparing graph features to a baseline model.

**2:45–3:00 — Closing**
Show the GitHub repository and v0.1.0 release (after you have actually published them). Thank the advisor.

Recording options: Windows Snipping Tool screen recording, OBS Studio, or Zoom. Record your actual screen and voice; this document is a script, not a generated video.
