# Route-census findings

Analyzer/census revision: `6343207`. The dual target/baseline inventory was
built execution-free for all 60 frozen corpus PRs with the configured app roots.
It does not change any score or confidence.

## Primary scores remain unchanged

| Backend | TP | FP | FN | FN in LOW | FN without candidate |
|---|---:|---:|---:|---:|---:|
| mypy | 3 | 0 | 68 | 0 | 68 |
| calibrated SCIP | 0 | 0 | 71 | 4 | 67 |

## Normalized FN stages

| Backend | Observation missing | Propagation missing | Discovery missing | Inventory unavailable | Total FN |
|---|---:|---:|---:|---:|---:|
| mypy | 0 | 20 | **48** | 0 | 68 |
| calibrated SCIP | 4 | 19 | **48** | 0 | 71 |

Definitions are operational:

- observation missing: truth matched only by LOW;
- propagation missing: route exists in target/baseline inventory but no primary
  or remaining LOW prediction reaches it;
- discovery missing: route is absent from both complete configured secure-AST
  inventories;
- inventory unavailable: partial/unresolved inventory prevents classification.

## Repository split

| Repository | mypy propagation/discovery | SCIP observation/propagation/discovery |
|---|---:|---:|
| Khoj | 0 / **32** | 0 / 0 / **32** |
| Langflow | 0 / **16** | 0 / 0 / **16** |
| Open WebUI | **20** / 0 | 4 / **19** / 0 |

## Decision

The first recall-producing slice must be **route discovery/application-root
composition**, not finite points-to globally:

1. Khoj and Langflow contribute all 48 discovery-stage FN.
2. Open WebUI discovery is complete for the remaining verification truth; its
   20/19 FN are propagation/observation work.
3. Finite points-to/delegate/executor dispatch remains the right next step for
   Open WebUI #26911, but it cannot help routes absent from the registry.

Immediate discovery investigation should compare configured app roots and entry
app symbols, then add only explicit/finitely proven roots, application factories,
bootstrap registration summaries, mounted/imperative routes, and WebSocket
registration forms. Static absence is not runtime absence and must not justify
truth deletion.

## Census health

The full corpus produced 39 completed, 19 partial, and 2 unresolved records.
All selected verification FN were nevertheless classifiable: known route IDs in
partial records can establish propagation, while discovery is assigned only
from complete dual inventories. Manifest and evaluations include clean candidate,
corpus, lock, command, selection, and output hashes.
