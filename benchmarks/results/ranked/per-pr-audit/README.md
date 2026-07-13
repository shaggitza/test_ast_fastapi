# Per-PR observability audit

This directory contains one source-backed report for every truth-positive PR in
`fastapi-adapter-v1`.

Start with [summary.md](summary.md) for the 177-atom accounting, failure
taxonomy, and repair priorities. Repository subdirectories contain the 26
individual reports.

Each report separates:

- complete canonical truth from scored FastAPI truth;
- HIGH/MEDIUM primary TP, FP, and FN from LOW diagnostics;
- route discovery, call propagation, semantic matching, and behavioral
  observation;
- established source evidence from runtime/configuration unknowns.

The counts describe the frozen ranked artifacts at analyzer revision `de31b3a`.
Subsequent confidence-policy experiments must be stored separately rather than
rewriting this audit baseline.
