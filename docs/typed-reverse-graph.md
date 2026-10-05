# Typed reverse impact graph prototype

`fastapi_endpoint_detector.analyzer.typed_reverse_graph` builds one immutable,
snapshot-local call/reference graph from retained mypy `MypyFile` trees and a
canonical source inventory. It does not call `MypyAnalyzer.analyze_endpoint` to
construct edges. `build_typed_reverse_graph` validates inventory paths and
source hashes, records engine/config/provider provenance, and emits one witness
for every physical call or supported global reference. Querying starts from
side-qualified changed symbols and follows caller edges in reverse, preserving
all route occurrence bindings and reconvergent physical paths.

The graph records exact mypy-resolved call targets and explicit-import aliases.
It does not invent targets for unresolved names or match module names by suffix.
Calls carry source coordinates, confidence, execution/reference state, formal
argument bindings, receiver identity, and an argument environment. Constructors
target the typed `__init__`; global reads and writes are represented separately.
Directly invoked lambda bodies are distinguished from deferred lambda bodies.

Each query has independent node, depth, enqueue, frontier, and witness budgets.
The result always carries explicit cap reasons and affected seeds. If traversal
was truncated, any returned HIGH evidence is downgraded to LOW. Baseline
deletions are queried against the baseline graph; target additions are queried
against the target graph. Coordinates are mapped only inside the selected
side's validated source inventory. A route and each declared dependency must be
supplied as separate physical `EndpointOccurrenceBinding` values. Conditional
routes must enter with LOW confidence.

`TypedGraphCache` currently provides provenance keying and strict reuse
validation, not persistent serialization. Its key includes schema, canonical
root/inventory/source hashes, engine/version, configuration fingerprint, and
provider graph provenance. Validation rejects mismatched roots, changed bytes,
symlinks, paths outside the root, and schema changes.

## Minimal integration plan

After the retained provider from PR #326 is available on the integration
branch:

1. Build/retain the typed snapshot once for each canonical target and baseline
   inventory.
2. Bind each discovered handler and dependency occurrence to its exact typed
   fullname and physical registration/source span. Keep same-handler route
   registrations as separate occurrence IDs.
3. Build one graph per snapshot, map added target and removed baseline hunks to
   exact symbol seeds, and query the matching side.
4. Convert `ImpactEvidence` back to existing mapper evidence while retaining
   physical call coordinates and the existing effect/conditional-route caps.
5. Keep the new path behind an explicit opt-in switch until full-depth parity,
   corpus candidate/evidence retention, and phase benchmarks pass. Rollback is
   an explicit caller choice; the graph does not switch itself on.

The final wiring belongs in `mypy_analyzer.py` and `change_mapper.py`, which
were intentionally left untouched in this branch. The current graph still has
material integration gaps: it does not import the analyzer's finite DI
callable/parameter/receiver points-to environments; it handles only mypy's
direct typed dispatch target, not its finite virtual target sets; assigned or
returned lambdas need execution-state transfer from the callable analyzer; and
effect, deferred-generator, dependency, and conditional route summary
propagation is not wired. Dependency occurrence bindings must currently come
from the existing runtime/native route evidence. Consequently this module is a
reviewable step toward GH107, not proof that GH107 is closed or safe to enable
by default.

## Focused parity and performance run

Run the trusted generated fixture with:

```sh
uv run python benchmarks/typed_reverse_graph_parity.py --modules 24 --samples 5
```

It compares positive and negative candidate sets, plus a one-file edited
snapshot, to exact changed-function frame membership in the current
full-depth `MypyAnalyzer.analyze_endpoint` output. Any mismatch stops the run.
It prints raw sample timings and empirical p95 values for cold typed build,
cold graph construction, warm graph query, one-file full typed rebuild, and
one-file graph reconstruction. Because the retained provider is not on this
base branch, the one-file timing is explicitly a fresh full typed rebuild; it
must not be read as incremental update latency. The generated DAG does not
establish production-corpus parity or cover DI, multi-target dispatch, effects,
conditional routes, deletion mapping, or every analyzer evidence type.

One recorded run on Python 3.11.16 / mypy 1.19.1 (24 modules, five samples,
15 exact oracle checks) reported p95s of 3.233 s for typed cold build, 0.094 s
for graph construction, 0.532 ms for a warm query, 3.513 s for the fresh full
typed rebuild after one-file change, and 0.123 s for graph reconstruction.
These are generated-fixture observations, not latency targets or corpus
performance claims.
