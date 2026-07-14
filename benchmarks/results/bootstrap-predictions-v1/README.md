# Bootstrap-aware prediction run v1

Clean mypy corpus run from commit `c05dfef`, using the explicit app/bootstrap configuration published by route-census bootstrap v4.

- `mypy/`: predictions, manifest, evaluation, and findings.
- `scip-unavailable/`: failed-attempt manifest only. The pinned external SCIP tools were not installed, every analyzable PR failed explicitly, and no SCIP score is published.

Primary scoring and LOW diagnostics follow `benchmarks/real_world/confidence-scoring.md`.
