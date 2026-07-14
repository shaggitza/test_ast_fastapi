# Shared mypy analysis performance findings

## Correctness parity

Verification-v1 remains:

- normalized primary: 3 TP / 0 FP / 68 FN;
- LOW: 32 truth matches / 40 unmatched FP / 72 candidates;
- candidate ceiling: 35 TP / 40 FP / 36 FN.

Candidate IDs and confidence tiers match bootstrap-predictions-v1. Structured effect evidence differs only in ephemeral detached-worktree path prefixes and candidate provenance.

## Clean timing comparison

Both runs contain the same 27 completed analyzer records.

| Repository | v1 median | v2 median | Improvement | v1 max | v2 max |
|---|---:|---:|---:|---:|---:|
| Khoj | 16.015 s | 11.141 s | 30.4% | 45.988 s | 11.539 s |
| Langflow | 59.887 s | 19.724 s | 67.1% | 112.263 s | 20.765 s |
| Open WebUI | 95.371 s | 29.182 s | 69.4% | 178.296 s | 32.150 s |

Across all completed runs:

- median: 21.973 s → 11.524 s (47.6% improvement);
- maximum: 178.296 s → 32.150 s (82.0% improvement);
- summed analyzer time: 1291.785 s → 446.646 s (65.4% improvement).

The implementation removes repeated project inventory canonicalization, changed-file path scans, handler module scans, fullname resolution, and function-definition scans. It preserves full depth and analyzes every endpoint; no route filtering or conditional-depth reduction was used.

## Gate interpretation

The representative absolute target of 100 endpoints under 30 seconds is now met by Khoj and Langflow; Langflow analyzes roughly 250 routes in about 20 seconds. The largest Open WebUI cases remain around 30–32 seconds for roughly 488 routes.

Performance is still endpoint-centric. A seed-driven typed reverse graph remains the long-term architecture, particularly for repositories larger than the current corpus. The current optimization is a semantics-preserving amortization step, not a claim that complexity is fully solved.
