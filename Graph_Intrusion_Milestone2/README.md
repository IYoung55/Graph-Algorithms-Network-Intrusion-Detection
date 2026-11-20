# Graph Algorithms for Network Intrusion Detection — Milestone 2

**Version v0.2.0 | Full Sail University CSMS | Ivory Young**

This Python research prototype loads network-flow CSV files, builds a directed communication graph, computes node centrality, and exports heuristic review alerts. Milestone 2 adds fixed UTC time-window summaries and per-source median-baseline comparisons. **Alerts are not proof of malicious activity.** The included data is synthetic; there is no real-time packet capture, trained ML model, or validated CICIDS2017 evaluation.

## Run on Windows (PowerShell)
```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:PYTHONPATH="src"
python -m graph_ids --input data/sample_flows.csv --window-minutes 5
python -m unittest discover -s tests -v
```

## Run on macOS/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
PYTHONPATH=src python -m graph_ids --input data/sample_flows.csv --window-minutes 5
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Generated outputs
- `outputs/network_graph.png`: communication graph with red review-flagged sources
- `outputs/node_metrics.csv`: node degree metrics
- `outputs/review_alerts.csv`: original full-dataset heuristic flags
- `outputs/window_metrics.csv`: per-source, per-window traffic summary and flags
- `outputs/window_alerts.csv`: flagged time-window records and explanations

## CSV schema
`timestamp,src_ip,dst_ip,protocol,bytes,dst_port`

## Options
`--destination-threshold 5 --port-threshold 6 --window-minutes 5 --baseline-multiplier 2.0`

Baseline compares each source's window flow count with its median across **observed windows** only. Missing inactive windows are not imputed; this is an exploratory heuristic, not a statistically calibrated detector. Use authorized data only.

## GitHub release
Commit and push files to your existing repository, then create tag `v0.2.0` and attach the ZIP to the release. Capture a screenshot, update your project board, and send the release link to your advisor. No GitHub actions or advisor messages have been sent automatically.
