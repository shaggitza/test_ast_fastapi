# SCIP run unavailable

The bootstrap-aware SCIP run was attempted from the same clean candidate and corpus configuration, but pinned external `scip-query`/SCIP binaries were absent. The runner recorded explicit analyzer failures for every Python-analyzable PR; non-Python and unresolved-parent records remained unresolved for their normal reasons.

`manifest.json` is retained as failure provenance. Predictions and evaluation were deliberately removed so tool unavailability cannot be mistaken for a zero-recall analyzer result.
