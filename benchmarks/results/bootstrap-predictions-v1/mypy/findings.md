# Bootstrap-aware mypy findings

## Verification-v1 result

Primary normalized scoring remains conservative and unchanged:

- TP: 3
- FP: 0
- FN: 68
- precision: 1.000
- recall: 0.0423

The newly discovered routes materially change the diagnostic candidate tier:

| Diagnostic | Previous ranked mypy | Bootstrap-aware mypy |
|---|---:|---:|
| LOW truth matches | 0 | 32 |
| LOW unmatched FP | 9 | 40 |
| LOW candidates | 9 | 72 |
| Supplemental reachability-supported LOW | 9 | 9 |
| Diagnostic precision | 0.000 | 0.444 |
| Supported precision | 1.000 | 0.569 |

Candidate ceiling (not a product operating point): 35 TP / 40 FP / 36 FN, precision 0.467, recall 0.493.

## Repository split

- Khoj: 22/32 truth atoms recovered at LOW; 30 LOW FP; 10 atoms remain without candidates.
- Langflow: 10/16 recovered at LOW; 1 LOW FP; 6 remain without candidates.
- Open WebUI: no new truth matches; its 9 LOW candidates remain independently reachability-supported.

Remaining no-candidate atoms are concentrated in:

- six Khoj frontend-origin HTTP atoms (#1216, #1221, #1235);
- one separately deployed Khoj telemetry app atom (#1265);
- three Khoj propagation atoms (#1212 and #1292), involving offline dispatch and PDF converter construction/delegation;
- six Langflow semantic/plugin/deployment atoms (#13952, #13960, #13968, #13992).

## FN stages

With fresh predictions and bootstrap census:

- observation missing (LOW truth match): 32;
- propagation missing: 20;
- discovery missing: 0;
- inventory unavailable: 16.

This partition is diagnostic. LOW remains a primary FN and cannot consume HIGH/MEDIUM truth.

## Performance warning

Discovery recovery exposes a serious endpoint-centric mypy cost:

| Repository | Previous median analyzer time | New median |
|---|---:|---:|
| Khoj | 0.414 s | 16.015 s |
| Langflow | 0.918 s | 59.887 s |
| Open WebUI | 88.159 s | 95.371 s |

Across 27 completed runs, the new median is 21.973 s and maximum 178.296 s. This fails the intended +10% runtime gate. The recall slice is useful evidence but should not be promoted to a default operating mode until mypy dependency extraction is made seed-driven or otherwise amortized across endpoints.

## SCIP attempt

The environment lacked pinned `scip-query`/SCIP binaries. All analyzable SCIP runs failed explicitly as designed; no zero-result SCIP evaluation is treated as a benchmark score.
