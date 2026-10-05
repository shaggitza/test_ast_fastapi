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
It does not invent targets for unresolved names, guess instance dispatch from a
local variable spelling, or match module names by suffix. Calls carry full-call
and callee-token source spans, direct confidence, invocation kind,
execution/reference state, formal argument bindings, receiver identity, and an
argument environment. Constructors target the typed `__init__`; global reads
and writes are represented separately.
Directly invoked lambda bodies are distinguished from deferred lambda bodies.
Per-evidence uncertainty witnesses record unknown/external call bindings,
member dispatch, deferred lambda capture, dependency parameter transfer, and
unmodeled effect summaries. Evidence on a proven path is downgraded to LOW when
one of these omissions touches the path. When an unresolved relation has no
proven edge to the seed, `uncertain_evidence` emits a separate LOW potential
candidate with only exact supporting caller witnesses and the explicit
uncertainty; it never fabricates an edge. Uncertainty reason codes appear
alongside any traversal cap reason in `incomplete.reasons`. The cap boolean
remains specific to traversal budgets.

Each query has independent node, depth, enqueue, frontier, and witness budgets.
The result always carries explicit cap reasons and affected seeds. If traversal
was truncated, any returned HIGH evidence is downgraded to LOW. Baseline
deletions are queried against the baseline graph; target additions are queried
against the target graph. Coordinates are mapped only inside the selected
side's validated source inventory. A route and each declared dependency must be
supplied as separate physical `EndpointOccurrenceBinding` values. Conditional
routes set `conditional=True`; the immutable binding enforces LOW confidence.

`TypedGraphCache` currently provides provenance keying and strict reuse
validation, not persistent serialization. Its key includes schema, canonical
root/inventory/source hashes, engine/version, configuration fingerprint, and
provider graph provenance. Validation also requires the current `TypedBuild`,
and matches its exact cache fingerprint and full `source_digests_after` table
against the graph. It rejects mismatched roots, changed bytes, symlinks, paths
outside the root, schema changes, engine changes, and a different retained
provider build.

Mypy AST edge, callee-token and symbol spans, plus endpoint registration spans, are validated
against the exact source bytes, including end-line/end-column boundaries. Call
arguments retain both the actual expression type and formal parameter type
from the retained provider's `type_maps` when mypy has a finding; absent type
entries remain `None` rather than being guessed. Exact keyword formals are
resolved by formal name; after a starred positional actual, later positional
formals remain unresolved and are exposed as an `unknown_binding` uncertainty.

## Minimal integration plan

After the retained provider from PR #326 is available on the integration
branch:

1. Build/retain the typed snapshot once for each canonical target and baseline
   inventory.
2. Bind each discovered handler and dependency occurrence to its exact typed
   fullname and physical registration/source span. Keep same-handler route
   registrations as separate occurrence IDs. For each handler occurrence,
   populate `dependency_symbols` only from exact typed targets returned by the
   analyzer's finite Depends/Security resolver; the graph makes these edges
   LOW-confidence until callable and parameter transfer is proven. Pass
   `conditional=True` for conditional registrations so the binding enforces
   the LOW cap.
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
effect, deferred-generator, and conditional route summaries are not wired.
Uncertainty witnesses expose these omissions per impacted evidence but do not
recover the missing paths. Consequently this module is a reviewable step
toward GH107, not proof that GH107 is closed or safe to enable by default.

### Proposed parent-owned phase bridge

These are narrow patches for the owners of PRs #311, #312, and #326; they are
not applied here:

1. In #311, expose the already-retained `TypedBuild` (or a snapshot accessor)
and a public exact resolver for each endpoint's `Depends`/`Security` symbols.
The current private `_python_dependency_fullnames` returns source spellings;
the bridge must resolve each against the retained snapshot to an exact
`Symbol.fullname` or return a per-item unresolved status. It must not suffix
match. Construct one handler `EndpointOccurrenceBinding` per physical route
registration, pass its exact dependency symbols in `dependency_symbols`, and
set its confidence from conditional route discovery.
2. In #326, pass the update's `TypedBuild` and exact `BuildReport` provenance to
the graph builder after **each** retained update. Rebuild the graph from that
snapshot (no edge patching yet), reuse a cached graph only if
`TypedGraphCache.validate` succeeds against the full canonical inventory,
source bytes, engine, configuration, and provider fingerprint.
3. In #312, map added coordinates to target graph seeds and removed coordinates
to baseline graph seeds using `seeds_for_changed_coordinates`. Query each side
independently. Preserve every path's edge coordinates and uncertainty witnesses
when converting to mapper candidates. Any `incomplete.capped` or semantic
uncertainty keeps the candidate LOW and must survive the output as a reason;
do not merge path evidence by endpoint before storing witnesses.
4. Keep the feature behind an explicit opt-in setting and have the caller retain
the legacy mapper result for parity comparison and rollback. Compare terminal,
edge/witness, occurrence, confidence, uncertainty, effects, and route caps before
enabling it.

## Focused parity and performance run

Run the trusted generated fixture with:

```sh
uv run python benchmarks/typed_reverse_graph_parity.py --modules 24 --samples 5
```

It compares positive and negative candidates, plus a one-file edited snapshot,
against current full-depth `MypyAnalyzer.analyze_endpoint` evidence. For each
terminal-reaching call-stack path, it matches exact canonical target symbols,
callee-token byte ranges, resolved-call-site status, invocation kind, and
available positional/keyword argument bindings. The generated fixture's
package root is part of both analyzers' canonical module IDs; comparison does
not normalize by basename. It reports endpoint referenced files and symbol
ranges beside each physical occurrence, graph witness, confidence, execution
and reference state, argument/environment bindings, cap, and uncertainty. A
candidate, occurrence, terminal, coordinate, target, invocation, or binding
mismatch stops the run. Direct exact-call confidence and call-stack execution
state are checked.
It prints raw sample timings and empirical p95 values for retained provider
cold typing, independent full-depth oracle typing, cold graph construction,
warm query, actual one-file provider update, graph reconstruction from the
updated retained snapshot, fresh typed rebuild after the edit, and cold graph
construction from that fresh typed build. Endpoint dependencies have no
matching route-level cap or effect-summary fields, so those semantics cannot
be compared here. The generated DAG does not establish production-corpus parity
or cover DI transfer, multi-target dispatch, effect-helper closures,
conditional routes, baseline deletions, or every analyzer evidence type. Its
exact physical call paths therefore do not establish no-quality-regression for
GH107.

The latest recorded run on Python 3.11.16 / mypy 1.19.1 (24 modules, five
samples, 30 full-evidence checks) reported p95s of 5.403 s for retained provider
cold typing, 1.694 s for independent full-depth analyzer typing, 0.056 s for
cold graph construction, 0.196 ms for a warm query, 0.014 s for the actual
one-file provider update, 0.047 s for graph reconstruction from that updated
snapshot, 1.481 s for a fresh provider rebuild after the edit, 1.561 s for an
independent cold analyzer rebuild, and 0.046 s for graph construction from that
fresh typed build. Provider reports confirmed `incremental_update` and exactly
one updated module (the fixture's final `m23`) per sample. Positive graph route
evidence was LOW because effect transfer remains unmodeled; the endpoint oracle
does not encode route-level confidence, effect summaries, or graph caps. Those
dimensions remain non-comparable and GH107 acceptance remains open. These are
generated-fixture measurements, not latency targets or corpus performance
claims.
