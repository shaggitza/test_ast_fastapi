# Transitive re-export route census v3

Clean execution-free dual-snapshot census from commit `a83c415`, using census schema v2 and Langflow `main:create_app`.

This run combines whole-inventory strength semantics with bounded exact project-local router/app re-export resolution. Conditional route occurrences remain LOW-only and conditional inventories cannot prove propagation or exhaustive absence.

Artifacts:

- `census.jsonl`: 60 target/baseline inventories with occurrence and inventory strength.
- `manifest.json`: candidate/configuration/hash/timing provenance.
- `mypy-evaluation.json` and `scip-evaluation.json`: verification-v1 FN staging.
- `findings.md`: inventory and stage deltas.
