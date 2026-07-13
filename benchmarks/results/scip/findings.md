# SCIP backend — real-world corpus result

**Candidate:** see `manifest.json`  
**Mode:** `--scip --secure-ast`, pinned `scip-query` 0.16.0 and Sourcegraph `scip-python` 0.6.6.  
**Corpus:** 60 PRs (not 120); Review A and Review B provide 120 independent review records. Ground truth contains 58 evaluable PRs and 180 canonical entrypoints.

## Exact canonical-ID score

- TP: **0**
- FP: **4**
- FN: **180**
- precision / recall / F1: **0 / 0 / 0**
- prediction coverage: **58/58 evaluable PRs**
- unresolved items: **37**
- analyzer runs with latency: **21**; mean **42.96s**, max **139.63s**

By repository:

| Repository | TP | FP | FN |
|---|---:|---:|---:|
| Open WebUI | 0 | 0 | 63 |
| Langflow | 0 | 0 | 62 |
| Khoj | 0 | 4 | 55 |

The backend emitted four endpoint IDs across three Khoj PRs. They were
router-local paths such as `/chat`, `/stats`, and `/update`, not the canonical
externally mounted paths, so all four count as false positives.

## Interpretation

SCIP itself succeeded on the controlled transitive fixture (2/2 endpoint
positives, no false positive). The real-world failure is dominated by the
framework adapter and corpus breadth: missing APIRouter/mount prefix composition,
non-HTTP/UI/event entrypoints, deleted-symbol baseline requirements, and 31
non-Python PRs. Replacing mypy with SCIP is therefore necessary as a semantic
foundation but not sufficient; the next work must be public-route composition
and additional framework adapters.
