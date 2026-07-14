# Conditional factory route census v2

This is a clean, execution-free dual-snapshot census from commit `82c723d`, using the same repository roots as route-census v1 plus the explicit Langflow entry `main:create_app`.

Conditional discovery retains only statically proven registrations across unknown app-mutating calls. It does not invent routes from plugin helpers. Every recovered Langflow occurrence is marked `conditional` with source path, line, and reason; analyzer confidence through such routes is capped at LOW.

Artifacts:

- `census.jsonl`: target/baseline inventory for all 60 corpus PRs.
- `manifest.json`: candidate, lockfile, configuration, hashes, status, and timing provenance.
- `mypy-evaluation.json`: verification-v1 FN staging against ranked mypy predictions.
- `scip-evaluation.json`: verification-v1 FN staging against calibrated SCIP predictions.
- `findings.md`: before/after interpretation.

The census remains diagnostic-only and cannot change TP/FP/FN or candidate confidence.
