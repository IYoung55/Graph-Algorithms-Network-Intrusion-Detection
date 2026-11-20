# Milestone 1 progress report — v0.1.0

## Goal
Establish a reproducible offline network graph analysis pipeline suitable for later research into graph-based intrusion detection.

## Implemented
1. CSV flow ingestion with required-field, IP, numeric, and timestamp validation.
2. Directed graph construction using NetworkX, with per-edge flow counts and total bytes.
3. Degree centrality and in/out degree metrics exported to CSV.
4. Transparent heuristic review flags based on unique destinations and ports.
5. Static PNG visualization with flagged sources highlighted.
6. Automated unit tests for core behaviors and validation.

## Limitations
- Synthetic demonstration data only; no empirical detection claims.
- Heuristic thresholds are not learned or calibrated; benign scans can be flagged.
- No time-window aggregation, real-time traffic ingestion, model training, authentication, or database.
- Dense graphs may be difficult to visualize and computationally expensive.

## Verification checklist
- [ ] Install dependencies and run the CLI locally.
- [ ] Confirm PNG and two CSV files appear in `outputs/`.
- [ ] Run unit tests successfully and capture results.
- [ ] Push repository and attach screenshot.
- [ ] Publish v0.1.0 ZIP/release and share with advisor.
- [ ] Record screencast and submit LMS links.

## Milestone 2 proposed work
- Add sliding-window flow aggregation and timestamp-aware features.
- Evaluate against a properly documented labeled dataset.
- Implement a simple baseline classifier for comparison.
- Report precision, recall, F1, and confusion matrix on held-out data.
- Improve graph layout and filtering for usability.
