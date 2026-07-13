# False-positive source audit

The apparent FP population was split into per-backend/per-PR disagreement
packets under `inputs/`, then reviewed against frozen Open WebUI merge snapshots
in disjoint route-family buckets. Complete final reports are under `reviews/`.
The residual, source-confirmed FP IDs are machine-readable under
`classifications/`.

## Outcome

- PR #26906: 2 omitted HTTP entrypoints and 10 genuine FPs.
- PR #26911: the sole unmatched SCIP prediction is a genuine FP; its 14
  remaining FNs are already represented in truth.
- PR #26642: 91 omitted HTTP entrypoints were source-confirmed. They include
  direct `Config.upsert` callers, provider/event routes, OAuth callbacks,
  frontend-to-API directory flows, chat/provider paths, and changed web-search
  behavior. Remaining predictions were classified as structural/call-graph
  over-approximation; `reviews/pr26642-root.md` closes the residual root-route
  bucket missed by the parallel prefix partition.

The 93 additions are recorded separately in
`benchmarks/real_world/adjudication-amendments.jsonl` and applied to the
canonical adjudication with `apply_adjudication_amendments.py`. Original Review
A and Review B files remain untouched. Each added label links back to its full
source audit.

## Interpretation

Before this audit, valid transitive route predictions were incorrectly charged
as FPs. On the versioned FastAPI-adapter scope, normalized mypy is now
95 TP / 19 FP / 82 FN (83.33% precision), while normalized SCIP is
110 TP / 371 FP / 67 FN (22.87% precision). SCIP still has broad structural
fanout, but the prior benchmark overstated that problem substantially.

Regenerate disagreement packets with `build_disagreement_audit.py` after any
truth or prediction change.
