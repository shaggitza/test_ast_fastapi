# Handler signature dependency candidates

This layer extends the source dependency metadata API from PR #394. The ordinary-build bridge
inspects annotations and default expressions in each exact handler signature using the retained,
hash-authenticated source bytes and the retained typed argument nodes. It does not import or
execute project source.

Candidates with a finite Depends or Security spelling, including explicit import aliases discovered across module-level control-flow suites, retain
their physical call span and each owning route occurrence. The collector distinguishes missing or
ambiguous typed calls, project-local shadows, unsupported argument binding, and provider identity
that is not the exact function node in a retained project module symbol table.

Every collected row is a SourceDependencyUncertainty. Even a canonical-looking FastAPI selector
fullname with an exact project provider remains fastapi_selector_origin_unverified. A declaration
fullname or an adjacent package hash does not authenticate the selector implementation; this layer
emits no positive dependency binding and infers no invocation or execution. String annotations are
not expanded. Route decorators, module-level dependency declarations, and handler bodies are
outside this signature scan. These limits are recorded in graph limitations.

Module import candidate discovery follows explicit if, try/except/else/finally, context-manager,
loop and match suites while excluding function and class bodies. A selector alias remains a
candidate across conflicting imports; this does not establish which binding exists at runtime.
Module statements and import bindings each have a 32,768-item budget. The signature scan bounds
syntax and typed nodes to 32,768 per handler, candidate calls to 64 per handler, and output rows
to 8,192. Excess fails with TypedGraphBridgeError rather than truncating silently.
If the host syntax parser cannot parse retained source accepted by the target mypy build, the
collector records a handler-span parse-unavailable uncertainty and preserves the existing graph.

Validation performed while authoring: Ruff check and format; strict type checking of 67 composed
production BuildSource entries with cache disabled; independent review of the exact source and
test blobs; 20 controls exercising the actual collector and metadata admission using manually
constructed typed nodes and inert in-memory syntax. The hosted tests cover shared-handler routes,
aliased selectors, positional and keyword declarations, local shadows, the body-scan boundary, and
the call budget. Physical project fixtures were authored for CI and were not executed in that
source-only validation.

GH107 remains open. Authenticated FastAPI selector ownership, positive declarations, additional
dependency declaration scopes, baseline/target parity, corpus/adversarial parity, and performance
acceptance require separate evidence.
