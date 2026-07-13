# Ranked-confidence full corpus evaluation

Analyzer revision: `de31b3a` on the 60-PR frozen corpus.
Scope: `fastapi-adapter-v1` (174 behavioral labels, 177 normalized atoms).

Policy: HIGH and MEDIUM form the primary score. LOW is diagnostic only and
never changes primary TP, FP, FN, precision, recall, or F1.

## Primary normalized score

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy | **95** | **10** | 82 | **90.48%** | 53.67% | **67.38%** |
| SCIP | **110** | 371 | **67** | 22.87% | **62.15%** | 33.43% |

## Primary raw exact score

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy | 91 | **17** | 83 | **84.26%** | 52.30% | **64.54%** |
| SCIP | **106** | 377 | **68** | 21.95% | **60.92%** | 32.27% |

## LOW diagnostics

| Backend | LOW candidates | Behavioral LOW TP | Behavioral LOW FP | Reachability-supported | Unmatched | Primary FN with LOW candidate | Primary FN with no candidate |
|---|---:|---:|---:|---:|---:|---:|---:|
| mypy | 9 | 0 | 9 | **9** | **0** | 0 | 82 normalized / 83 exact |
| SCIP | 0 | 0 | 0 | 0 | 0 | 0 | 67 normalized / 68 exact |

The nine mypy LOW candidates are the Open WebUI #26906 task/compaction routes.
They are outside behavioral ground truth but independently source-confirmed to
execute the changed defensive-copy path. Therefore they are reported as nine
behavioral LOW FPs **and** nine reachability-supported candidates, with zero
unmatched LOW noise. They do not reduce primary precision.

No LOW candidate recovers a behavioral FN in this run. Consequently the
candidate ceiling has the same recall as primary. For mypy, including LOW as
ordinary predictions would only reduce normalized precision from 90.48% to
83.33%, demonstrating why LOW must remain diagnostic.

## Candidate distribution

| Backend | HIGH | MEDIUM | LOW | PRs with candidates | Effect evidence records |
|---|---:|---:|---:|---:|---:|
| mypy | 10 | 98 | 9 | 2 | 262 |
| SCIP | 10 | 473 | 0 | 3 | 1,411 |

SCIP's remaining problem is not LOW-candidate handling: 473 candidates are
still MEDIUM because reference reachability lacks an effect-aware downgrade.
Its next precision step is to add data-observation evidence to SCIP paths or
require mypy/data-flow corroboration before MEDIUM assignment.

Mypy remains concentrated in Open WebUI and still has zero recall on Langflow
and Khoj. Confidence ranking improves selective precision but does not solve
adapter/propagation coverage on those repositories.
