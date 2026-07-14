# Observation-calibrated SCIP baseline

Analyzer revision: `3bff609` on the frozen 60-PR corpus.

This baseline supersedes the permissive SCIP primary score for product-facing
claims. Direct changed endpoint definitions remain HIGH. Every transitive SCIP
reverse-reference result remains LOW until independently corroborated by
endpoint-visible data-flow/effect evidence.

## Normalized score

| Operating point | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Primary HIGH/MEDIUM | 9 | 0 | 168 | 100.00% | 5.08% | 9.68% |
| Historical candidate ceiling | 110 | 371 | 67 | 22.87% | 62.15% | 33.43% |

LOW diagnostics:

- 472 normalized LOW atoms;
- 101 primary FN atoms have a matching LOW candidate;
- 67 primary FN atoms have no candidate;
- 371 LOW atoms do not match current behavioral truth;
- diagnostic LOW precision: 21.40%.

Raw exact primary is 5 TP / 5 FP / 169 FN. The normalized 9/0 result benefits
from conservative method/alias normalization; raw and normalized remain
co-reported.

## Repository distribution

| Repository | TP | FP | FN | Recall |
|---|---:|---:|---:|---:|
| Open WebUI | 9 | 0 | 120 | 6.98% |
| Langflow | 0 | 0 | 16 | 0% |
| Khoj | 0 | 0 | 32 | 0% |

The 100% primary precision is therefore not useful coverage. It says only that
the nine selected normalized atoms are supported; it does not make the analyzer
production-ready.

## Engineering outcome

- 26 per-PR source audits explain all 177 truth atoms.
- Fixed-point explicit inheritance expansion was added with no corpus noise or
  runtime regression.
- The pinned `scip-query refs` schema was verified and a fail-closed direct call
  edge API was added, but it is not used in production mapping yet.
- A runtime effect-path trial produced no candidate/TP gain and increased median
  latency by 26.9%; it was rolled back under the documented stop rules.
- Next coverage work must model finite factory/delegate/executor/override
  dispatch as LOW-only reachability before any observation-based promotion.

See `benchmarks/results/ranked/per-pr-audit/summary.md` and
`benchmarks/results/ranked/per-pr-audit/repair-experiments.md` for source
evidence and the repair taxonomy.
