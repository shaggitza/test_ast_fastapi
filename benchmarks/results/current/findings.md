# Current analyzer — real-world corpus result

**Candidate:** `fastapi-endpoint-detector/0.1.0/4938b505adf2/4bc699fd8b44`  
**Mode:** secure AST endpoint discovery plus mypy dependency analysis; upstream code was not imported or executed.  
**Corpus:** 60 frozen PRs; 58 adjudicated and 2 `not_evaluable`.

## Score

| Metric | Result |
|---|---:|
| Prediction coverage | 100% (58/58 evaluable PRs) |
| Micro precision | 0.000 |
| Micro recall | 0.000 |
| Micro F1 | 0.000 |
| TP / FP / FN | 0 / 40 / 180 |
| Unresolved items | 39 |
| Analyzer latency samples | 27 |
| Mean / max analyzer latency | 9.64s / 19.01s |

The two release-scale `not_evaluable` PRs were attempted but excluded from the
score. Their merge parents were intentionally left unresolved rather than
guessed.

## What failed

The secure detector emitted 40 HTTP identities, all from Khoj, but none matched
the canonical adjudicated IDs. The dominant cause is missing router and mount
prefix composition: for example, router-local paths such as `/chat`, `/types`,
and `/update` were emitted without their externally mounted `/api` prefixes.
It emitted no endpoint for the evaluated Open WebUI or Langflow changes.

This is not only a normalization problem. The 180 ground-truth positives contain
78 HTTP, 73 other/UI, 13 event, 8 CLI, 4 SDK, 3 cron, and 1 task entrypoints.
A FastAPI-only adapter cannot cover most of the corpus, while middleware,
persistence, component, frontend, and configuration changes often require
transitive framework-aware mapping even within the HTTP subset.

Unresolved evidence comprises 31 explicit non-Python skips, the two ambiguous
release-merge parents, and six endpoints whose decorator paths were not static
strings. Skips remained visible and therefore could not improve recall.

## Interpretation

The controlled FastAPI fixture remains valuable and the implementation can
serve as a focused adapter/prototype, but this real-world score rejects it as a
standalone general blast-radius engine. Improving hand-built router resolution
would address some false positives, yet would not solve Java, TypeScript,
frontend, event, CLI, SDK, task, or cross-repository impact.

The result strengthens the **HYBRID** recommendation:

1. adopt compiler/SCIP or LSP-backed symbol and reference indexes as the
   language layer;
2. retain thin framework adapters for canonical entrypoint identities and
   mounted-route composition;
3. attach dedicated contract analyzers separately;
4. keep uncertainty and unsupported entrypoint kinds explicit rather than
   silently returning empty impact.

`predictions.jsonl`, `manifest.json`, and `evaluation.json` contain the complete
machine-readable reproduction evidence.
