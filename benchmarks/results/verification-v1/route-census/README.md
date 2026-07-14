# Route-census FN diagnostics

Schema v1 stores one record per corpus PR with separate target and baseline
secure-AST inventories. Every public route ID retains its physical handler
occurrences and configured root provenance. The manifest records candidate,
corpus, lock, root, command, status, timing, and output hashes.

`evaluate.py --route-census` partitions primary FN in this order:

1. `observation_missing`: truth matched only by LOW. This operational name does
   not prove that effect analysis is the only defect.
2. `propagation_missing`: no LOW match, but the route exists in target or
   baseline inventory.
3. `discovery_missing`: absent from both sides of a complete configured static
   inventory. Static absence is not proof of runtime absence.
4. `inventory_unavailable`: missing, partial, or unresolved inventory prevents
   classification.

Invariant, globally and per PR/repository:

```text
FN = observation_missing + propagation_missing
   + discovery_missing + inventory_unavailable
```

Baseline presence prevents deleted routes from being called discovery misses.
The census is never passed to matching as a prediction and cannot alter any
score or candidate confidence. Full corpus artifacts are intentionally deferred
until the implementation is committed and run from a clean revision.
