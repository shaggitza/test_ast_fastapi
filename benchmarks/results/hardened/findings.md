# Hardened mypy vs SCIP real-world score

Candidate commit: `1976a234fe180bce9df766481f7c646b7801e1e7`.
The subsequent structural-confidence change does not alter the two PRs that
emitted predictions; both were rechecked before merging that policy.

Corpus: 60 PRs, 58 adjudicated/evaluable, 180 total labels. Only 78 evaluable
labels are HTTP; the remaining 102 are CLI, cron, event, UI/other, SDK, or task
entrypoints outside the current FastAPI HTTP adapter.

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy | 10 | 257 | 170 | 3.75% | 5.56% | 4.47% |
| SCIP dual snapshot | 11 | 467 | 169 | 2.30% | 6.11% | 3.34% |

Conservative semantic normalization (composite methods, compatible template
names, WebSocket casing, unique qualifiers, and frozen evidence-backed aliases)
keeps the raw score above unchanged and adds:

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy normalized | 14 | 250 | 169 | 5.30% | 7.65% | 6.26% |
| SCIP normalized | 15 | 461 | 168 | 3.15% | 8.20% | 4.55% |

The normalized truth contains 183 atomic claims because the four-method OpenAI
catch-all expands from one display label into four independently matchable
operations. Raw metrics remain the historical primary record.

HTTP-only:

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy | 10 | 256 | 68 | 3.76% | 12.82% | 5.81% |
| SCIP dual snapshot | 11 | 467 | 67 | 2.30% | 14.10% | 3.96% |

Both backends emitted predictions on two PRs. Almost all false positives come
from Open WebUI PR #26642, a 107-file change where shared configuration/schema
symbols fan out to hundreds of routes. Exact ground truth labels only 14 public
surfaces, while compiler reachability conservatively marks every structural
consumer. This is now the dominant precision boundary: compiler call graphs do
not provide path-sensitive data-flow or runtime configuration guards.

Improvements relative to the initial scores:

- mypy: from 0 TP / 40 FP / 180 FN to 10 TP / 257 FP / 170 FN;
- SCIP: from 0 TP / 4 FP / 180 FN to 11 TP / 467 FP / 169 FN;
- route composition, application factories, WebSockets, exact handler identity,
  safe caches, target/baseline snapshots, deletions, and exact SCIP seed checks
  are now implemented;
- SCIP has slightly better recall; mypy has better precision and latency.

The FP increase is not a route-prefix regression. Correct composition and dual
baseline traversal expose real compiler-reachable routes that the earlier
broken adapters never emitted. The remaining work requires a data-flow/config
layer or consensus policy above compiler reachability, plus additional adapters
for the 102 non-HTTP labels. Raw artifacts and manifests are stored beside this
report.
