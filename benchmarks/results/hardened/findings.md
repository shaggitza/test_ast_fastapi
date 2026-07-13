# Hardened mypy vs SCIP real-world score

Candidate commit: `14cdd876add4571413b55f982ec4ad62d8e42e80`.

Corpus: 60 PRs, 58 adjudicated/evaluable, 180 raw labels. Of those, 78 are
HTTP; the remaining 102 are CLI, cron, event, UI/other, SDK, or task entrypoints
outside the current FastAPI HTTP adapter.

## Raw exact score

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy | 10 | 107 | 170 | 8.55% | 5.56% | 6.73% |
| SCIP dual snapshot + override edges | 15 | 468 | 165 | 3.11% | 8.33% | 4.52% |

## Conservative normalized score

Normalization expands composite methods and handles compatible template names,
WebSocket casing, unique qualifiers, and frozen evidence-backed aliases. Raw
metrics above remain unchanged and auditable.

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy normalized | 14 | 100 | 169 | 12.28% | 7.65% | 9.43% |
| SCIP normalized | 19 | 462 | 164 | 3.95% | 10.38% | 5.72% |

The normalized truth contains 183 atomic claims because the four-method OpenAI
catch-all expands from one display label into four independently matchable
operations.

## HTTP-only

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy raw | 10 | 107 | 68 | 8.55% | 12.82% | 10.26% |
| mypy normalized | 14 | 100 | 67 | 12.28% | 17.28% | 14.36% |
| SCIP raw | 15 | 468 | 63 | 3.11% | 19.23% | 5.35% |
| SCIP normalized | 19 | 462 | 62 | 3.95% | 23.46% | 6.76% |

## What changed

- Semantic evaluation no longer scores one composite HTTP label as one FN plus
  four method-specific FPs.
- Removing the mypy ±3-line heuristic cut the dominant PR #26642 prediction set
  from 254 to 104 while retaining all 9 raw TP: its FP count fell from 245 to 95.
- Exact `Annotated[..., Depends/Security(...)]`, nested DI, injected member calls,
  imported globals, and constructor/`__init__` evidence are modeled by mypy.
- SCIP seed failures are isolated per symbol instead of aborting a PR.
- Explicit concrete-to-base override edges recover four HTTP labels on Open
  WebUI PR #26911 with one additional FP.

SCIP now has materially better HTTP recall; mypy has materially better precision
and latency. Remaining misses are dominated by non-Python/non-HTTP scope,
persistent-state effects, dynamic plugin/registry dispatch, ORM/data-flow
semantics, and conditional runtime behavior. Remaining SCIP FP is still
dominated by broad compiler reachability in Open WebUI PR #26642.
