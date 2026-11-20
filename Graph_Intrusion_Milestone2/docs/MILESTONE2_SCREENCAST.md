# Milestone 2 Screencast Script (3–4 minutes)

**0:00–0:30 — Introduction:** My capstone is Graph Algorithms for Network Intrusion Detection. This is the second milestone, build v0.2.0.

**0:30–1:15 — Code:** Show `src/graph_ids/core.py` and describe CSV validation, graph creation, and the new `analyze_windows` function. Explain that each source is summarized into fixed UTC windows.

**1:15–2:15 — Live demonstration:** Run `python -m graph_ids --input data/sample_flows.csv --window-minutes 5`. Show `outputs/network_graph.png`, `window_metrics.csv`, and `window_alerts.csv`. Explain that red nodes and REVIEW_REQUIRED labels are heuristic review signals, not confirmed attacks.

**2:15–2:45 — Testing:** Run `python -m unittest discover -s tests -v` and show the passing test output. Discuss parameter validation and window boundaries.

**2:45–3:20 — Version control:** Show the GitHub commit, v0.2.0 release and project board once you have uploaded them.

**3:20–3:45 — Conclusion:** The next stage is evaluating on labeled, authorized network traffic and improving usability. Thank you.

Only describe steps you have actually completed; do not claim the advisor reviewed the project until they have.
