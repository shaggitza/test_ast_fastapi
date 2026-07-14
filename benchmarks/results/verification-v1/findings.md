# FastAPI verification v1

Primary verification excludes Open WebUI #26642 and retains it as a separately
reported stress holdout. Canonical truth and `fastapi-adapter-v1` membership are
unchanged.

The set contains 59 of 60 corpus PRs, of which 57 are adjudicated/evaluable in
the current artifact, 25 are truth-positive, and 71 normalized FastAPI atoms
are scored.

## Normalized primary

| Backend | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| mypy | 3 | 0 | 68 | 100% | 4.23% | 8.11% |
| SCIP calibrated | 0 | 0 | 71 | 0% | 0% | 0% |

## LOW diagnostics

| Backend | FN found in LOW | FN without candidate | LOW candidates | LOW unmatched | Reachability-supported LOW |
|---|---:|---:|---:|---:|---:|
| mypy | 0 | 68 | 9 | 0 | 9 |
| SCIP calibrated | 4 | 67 | 6 | 2 | 0 |

## Stress holdout: Open WebUI #26642

| Backend | Primary TP/FP/FN | FN found in LOW | LOW FP |
|---|---:|---:|---:|
| mypy | 92/10/14 | 0 | 0 |
| SCIP calibrated | 9/0/97 | 97 | 369 |

Machine-readable holdout evaluations are under
`stress-open-webui-26642/{mypy,scip}/evaluation.json`; each embeds the include
manifest SHA-256 and exact selected PR key.

The split exposes the corpus concentration directly: almost all selected
coverage came from one release aggregation. Excluding it does not improve the
analyzer; it shows that general cross-PR verification performance is currently
near zero.
