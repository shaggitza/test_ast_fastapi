# Repair experiments after the per-PR audit

All experiments used the frozen 60-PR corpus, `fastapi-adapter-v1`, pinned
`scip-query` 0.16.0 / `scip-python` 0.6.6, and the same repository roots.
Temporary artifacts were written under `/tmp`; historical `de31b3a` artifacts
were not overwritten.

## 1. Confidence calibration

The audit established that transitive SCIP output is reference/call
reachability, not endpoint-visible observation. The policy now keeps every
transitive result as LOW and keeps only direct changed endpoint definitions
HIGH.

Normalized result:

| Tier | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| Primary HIGH/MEDIUM | 9 | 0 | 168 | 100% | 5.08% |
| LOW diagnostic | 101 | 371 | — | 21.40% | — |
| Candidate ceiling | 110 | 371 | 67 | 22.87% | 62.15% |

This does not improve coverage. It corrects the claim: 101 behavioral truth
atoms are present only in LOW, while 371 LOW atoms are unsupported by current
behavioral truth. The old `110 TP / 371 FP / 67 FN` score was a permissive
reachability ceiling, not a defensible primary operating point.

## 2. Fixed-point explicit inheritance bridges

A deterministic bounded worklist replaced one-pass concrete-method-to-base
expansion. It preserves native candidates, closes over successive explicit
base bridges, retains minimum depths, terminates on cycles, and leaves every
transitive result LOW.

Corpus result: no selected or candidate delta on the frozen PRs. Median SCIP
incremental time changed from 32.15s to 31.79s; p95 from 82.88s to 83.72s.
The infrastructure is retained because generic two-bridge fixtures prove the
old one-pass algorithm incomplete without increasing corpus noise.

## 3. Pinned SCIP reference occurrences

`scip-query refs <full-symbol> --json` was verified empirically. Version 0.16.0
returns exact full-symbol resolution and reference **lines**, but no columns or
predecessor path:

```json
{
  "matched": true,
  "resolved": {"symbol": "...", "shortName": "...", "relativePath": "..."},
  "totalMatches": 1,
  "references": [{"relativePath": "main.py", "line": 3}]
}
```

A conservative direct-call-edge API was added. It rejects imports, bare value
references, ambiguous/multiple same-line references, unrelated same-terminal
calls, module-level references, malformed paths, traversal, and symlink escape.
It uses exact full-symbol resolution, AST callable-position validation, bounded
project paths, deterministic sorting, and caching.

## 4. Effect-path integration trial — rolled back

A bounded reverse BFS trial fed proven line-level call paths into the existing
defensive-copy effect analyzer. It was deliberately evaluated before release.

Result:

- normalized primary remained `9 TP / 0 FP / 168 FN`;
- LOW remained `101 TP / 371 FP`;
- Open WebUI #26906 remained one LOW SCIP candidate; none of the three
  behavioral routes or nine audited reachability-only routes were recovered;
- Open WebUI #26911 remained five LOW candidates;
- median incremental time increased from 31.79s to 40.33s (+26.9%);
- maximum increased from 142.62s to 241.94s.

This violated the audit stop rules (no TP/candidate gain and >10% median
runtime growth), so runtime path reconstruction and promotion were removed.
The direct-edge API and golden schema fixture remain as tested infrastructure,
but they are not invoked by production analysis.

## What this proves

The missing Langflow, Khoj, and Milvus routes are not fixed by replaying ordinary
SCIP references. Their gaps require explicit semantic primitives:

1. finite factory/constructor value targets;
2. constructor parameter to `self.field` delegate propagation;
3. resolved async/thread executor callable execution;
4. finite interface-to-implementation dispatch;
5. literal registry/re-export edges;
6. independent observation contracts before any LOW candidate is promoted.

Each primitive must first add LOW reachability with generic positive, negative,
and renamed-symbol tests. Promotion remains a separate evidence decision.
Frontend/deployment-origin PRs require separate adapters and applicability
scopes; removing the Python-change gate would only mislabel unsupported input.
