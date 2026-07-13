# Hardened mypy vs SCIP real-world score

Analyzer candidate: `14cdd876add4571413b55f982ec4ad62d8e42e80`.
Ground truth was subsequently amended by an evidence-backed FP source audit;
Review A and Review B remain unchanged.

## Scope correction

The complete corpus now has 273 adjudicated labels over 58 evaluable PRs.
The versioned `fastapi-adapter-v1` product scope contains 174 labels:
166 finite HTTP claims and 8 explicit WebSocket routes. The other 99 labels are
preserved under `out-of-scope-v1` for future UI, CLI, cron, SDK, task, generic
event, mounted-app, or wildcard adapters. They no longer depress the FastAPI
product recall.

Five labels annotated as HTTP are excluded from the adapter scope because they
are methodless, mounted-app, descriptive, or global wildcard claims that the
current method/path output contract cannot emit.

## FastAPI-adapter-v1 score

### Raw exact

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy | 91 | 26 | 83 | 77.78% | 52.30% | 62.54% |
| SCIP dual snapshot + override edges | 106 | 377 | 68 | 21.95% | 60.92% | 32.27% |

### Conservative semantic normalization

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy normalized | **95** | **19** | 82 | **83.33%** | 53.67% | **65.29%** |
| SCIP normalized | **110** | 371 | **67** | 22.87% | **62.15%** | 33.43% |

Raw exact scoring remains available alongside normalized atomic-claim scoring.
The normalized scope has 177 atoms because the four-method OpenAI catch-all
expands into four independently matched operations.

## Repository breakdown (normalized adapter scope)

| Backend | Repository | TP | FP | FN | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|
| mypy | Open WebUI | 95 | 19 | 34 | 83.33% | 73.64% |
| mypy | Langflow | 0 | 0 | 16 | 0% | 0% |
| mypy | Khoj | 0 | 0 | 32 | 0% | 0% |
| SCIP | Open WebUI | 110 | 371 | 19 | 22.87% | 85.27% |
| SCIP | Langflow | 0 | 0 | 16 | 0% | 0% |
| SCIP | Khoj | 0 | 0 | 32 | 0% | 0% |

The aggregate improvement is therefore real but concentrated in Open WebUI.
Neither backend currently emits predictions for the evaluated Langflow or Khoj
PRs.

## FP source audit

Parallel source audits examined normalized disagreements by PR and route family.
They found 93 valid HTTP surfaces omitted from the original adjudication:
91 on Open WebUI #26642 and 2 on #26906. Evidence and complete classification
reports live under `audit/`; machine-readable additions live in
`benchmarks/real_world/adjudication-amendments.jsonl`.

The remaining mypy FP set is small and mostly consists of call-reachable routes
without an observable changed behavior. SCIP still expands structural symbols
to many sibling CRUD routes, so path/data-flow and configuration corroboration
remain its primary precision need.

## Full all-surface view

For historical comparison, normalized all-surface metrics are:

- mypy: 95 TP / 19 FP / 181 FN, precision 83.33%, recall 34.42%.
- SCIP: 110 TP / 371 FP / 166 FN, precision 22.87%, recall 39.86%.

These recall values intentionally include the 99 claims requiring other
adapters and are not the FastAPI product score.
