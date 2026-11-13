# Graph Algorithms for Network Intrusion Detection — Milestone 1

**Build:** v0.1.0 | **Author:** Ivory Young | **Program:** Full Sail University CSMS

## Purpose
A runnable Python prototype that imports network flow CSV records, constructs a directed communication graph, calculates degree centrality, highlights nodes meeting simple activity thresholds, and exports a graph PNG and CSV reports.

**Important:** This is a teaching/research prototype, **not** a validated or production-ready intrusion detection system. A red node indicates a **heuristic review flag**, not proof of malicious activity. The included sample dataset is **synthetic**. There is no packet capture, real-time detection, trained ML model, or live network monitoring in this milestone.

## Requirements
- Python 3.10+ (3.11 recommended)
- Packages in `requirements.txt`

## Quick start (Windows PowerShell)
```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:PYTHONPATH="src"
python -m graph_ids --input data/sample_flows.csv
python -m unittest discover -s tests -v
```

## Quick start (macOS/Linux)
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
PYTHONPATH=src python -m graph_ids --input data/sample_flows.csv
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Outputs
- `outputs/network_graph.png`: directed network graph; flagged sources are red
- `outputs/node_metrics.csv`: in/out degrees and degree centrality
- `outputs/review_alerts.csv`: explainable threshold-based review flags

## Input CSV schema
`timestamp,src_ip,dst_ip,protocol,bytes,dst_port`

`timestamp` is parsed as UTC; `src_ip` and `dst_ip` must be valid IP addresses; `bytes` and `dst_port` must be nonnegative, and port must be an integer at most 65535.

## Heuristic configuration
```bash
PYTHONPATH=src python -m graph_ids --input data/sample_flows.csv --destination-threshold 5 --port-threshold 6
```
Flags sources with **at least 5 distinct destinations OR at least 6 distinct destination ports** over the entire imported dataset. This is not a time-windowed rate detector. Thresholds are illustrative and not tuned to a validated dataset.

## Repository and release
Follow `docs/GITHUB_SUBMISSION.md` to create your own GitHub repository, commit/push the code, publish a v0.1.0 release ZIP, and capture the required screenshot. **No GitHub repository or advisor notification has been created or sent on your behalf.**

## Next milestone
Time-windowed analysis, baseline comparison, labeled dataset evaluation, better anomaly methods, and usability improvements. See `docs/MILESTONE_REPORT.md`.
