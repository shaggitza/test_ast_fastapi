# Framework phase bridge v1

`framework_phase_bridge` maps only unchanged contracts from the bundled
`framework-v1` catalog to supported phase/range pairs. It accepts no
caller-provided identity, reachability, or strength flags. Arbitrary IDs,
symbols, phases, and ranges cannot establish a phase.

`collect_framework_phase_evidence` accepts a selected framework inventory,
its loaded versioned contracts, the existing `MypyAnalyzer`, and a retained
`MypyIncrementalProvider` typed build. It analyzes only selected callback
bodies, then joins a physical registration occurrence only when exactly one
mypy call site matches its file, line, and column and resolved invocation and
receiver identity. The typed framework declaration must belong to the
installed FastAPI or Starlette distribution and remain outside the selected
application source root. Mypy’s canonical symbol is retained as evidence.
Before accepting caller-supplied surfaces or activations, the adapter reruns
`CustomSurfaceExtractor` against the current source and contracts and requires
an exact model match, including registration and activation source hashes.
Records bind callback-range call sites to source, inventory, engine, and
contract-configuration digests. Startup-installed routes are projected
separately and remain conditional on successful startup.

Lifecycle decorators use the contract's full callback range. Lifespan startup
uses the pre-yield range, and lifespan shutdown uses the post-yield range.
Each record states that execution depends on the framework dispatching its
phase. Middleware records are request-dispatch conditional.

## Reported unavailable cases

Constructor lifespan registrations, imperative `add_event_handler`, and
other registration sites outside a selected callback's typed slice lack a
caller-scope query in the existing public mypy analyzer API. Their callback
bodies can still be analyzed, but exact registration identity remains
unavailable. BackgroundTasks use mypy's existing exact summaries; exporting
their callback target identity and phase witness needs a small typed analyzer
API hook. SCIP currently has no supported exact callback registration query,
so it cannot establish phase evidence. The adapter is not yet wired into the
CLI, report, or mapper.

## Runtime phase comparison

`compare_phase_artifacts` first calls the existing #307 comparator, which
validates artifact schema, pair equivalence, and provenance. Current trusted
artifacts contain no phase callback receipts, so even a valid successful
aggregate pair yields an unavailable phase result. Caller-provided booleans
and hash-shaped strings are not accepted as receipts. A real isolated phase
comparison remains gated on phase-aware trusted receipts and GH101 runtime
authority.

Synthetic tests exercise the selected-surface extractor, physical source to
mypy registration joins, callback phase slicing, retained typed declarations,
report projection, and exact reverse-graph symbol-span joins. They do not
create execution receipts or establish runtime truth.

## Integration hooks still required

This branch adds adapters only. To wire it without taking ownership of the
existing mapper or CLI, the smallest integration changes are:

1. The baseline CLI integration owner can call
   `collect_framework_phase_evidence` immediately after it has selected the
   framework surface inventory and obtained the retained mypy build, then
   attach `phase_report_payload(evidence)` to its report assembly. The source
   side must be passed independently for target and baseline. It should omit
   the field when the backend is SCIP until SCIP exposes exact callback-target
   provenance; a capability name alone is not evidence.
2. The mypy analyzer owner can expose a source-scoped exact call-site query
   taking `(path, line, column)` plus an optional caller scope. That lets the
   bridge match constructor lifespan and imperative event registrations that
   sit outside the callback body without expanding into framework code.
3. The mypy analyzer owner can expose its existing BackgroundTasks summary as
   typed callback witnesses containing the exact argument target, wrapper
   registration occurrence, execution condition, and source span. The bridge
   can then map those witnesses to the same typed record schema.
4. The retained provider owner can let `MypyAnalyzer` consume a `TypedBuild`
   snapshot directly. The current adapter separately invokes the analyzer and
   provider, so it verifies that both snapshots agree but can duplicate a
   mypy build.
5. The reverse-graph owner can call `adapt_framework_phases_to_graph` after
   building its graph. The adapter binds evidence to existing symbols only;
   it does not create edges or claim call reachability.

These hooks are proposals, not edits to existing owner files. Until the report
hook is integrated, the bridge is implemented and fixture-tested but not
present in normal CLI output. GH104 remains incomplete for those unwired
surfaces and for missing isolated runtime phase receipts.

## Tested source references

The composed unit fixtures ran on `origin/main` at
`838cf9c66d65ed8bdc93d13adee7decfcd86dfaf` with this branch's new bridge and
adapter files. That composition exercised the selected-surface extractor and
current `MypyAnalyzer` APIs plus PR #326's retained provider. The checked-out
heads `fd152759` (#303), `3b28c09` (#311), `9c3b070` (#312), `249b7e6` (#314),
`c750cb6` (#319), `609ed9f` (#321), `490c19c` (#322), and `39484fc` (#331)
were inspected for their surface, exact-callsite, diff, inventory, provenance,
SCIP, and graph APIs but were not merged into this test composition. The #307
comparator available on the baseline was exercised with synthetic aggregate
artifacts; the fetched PR #307 head `ad0cade` was not merged into this
composition. The graph adapter was tested against a structural fixture with
the PR #107 `TypedReverseGraph` symbol/span contract; it was not run against
that owner's builder/query implementation.
