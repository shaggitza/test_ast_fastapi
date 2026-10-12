# Source dependency metadata in the typed graph

Related task: GH107. This is a graph-ingestion boundary, not verified FastAPI dependency execution.

Graph schema 6 accepts optional bounded `SourceDependencyBinding` and
`SourceDependencyUncertainty` rows. Each row is tied to an existing route occurrence,
the exact typed function symbol and its physical span, and the authenticated inventory
path/module/SHA-256 and byte coordinates. Provider targets must be existing function
symbols with the same complete target span. Malformed scalar values, stale or outside-owner
spans, duplicate rows or route IDs, and more than 8192 total rows are rejected before
metadata sorting or lookup.

Bindings are caller-supplied declarations. The four admitted selector identities are
`fastapi.params.Depends`, `fastapi.params.Security`,
`fastapi.param_functions.Depends`, and `fastapi.param_functions.Security`.
Admitting one of these strings does not authenticate the selector's implementation or
prove that the source call injects the provider. No origin-attested collector is added
in this change.

The graph emits source-declaration evidence with LOW confidence and unknown invocation,
execution and reference state. Parameter transfer remains an explicit uncertainty.
Two registrations of the same handler keep two metadata rows and two query occurrences,
while sharing one physical source witness. Witness identity includes all physical
call/provider coordinates and excludes the route occurrence ID.

The cache manifest binds the full metadata rows, including occurrence IDs and all span
fields. Validation checks them again against the current authenticated bytes and verifies
the required metadata witnesses. Existing legacy `dependency_symbols` behavior and
the old limitations are preserved when both new inputs are absent or empty.

Validation performed in the read-only workspace: Ruff format/check, strict Mypy on the
exact graph module with in-memory source and no incremental cache, and 65 controls using
the actual metadata admission, builder, query and cache projection code on manually
seeded symbols and spans. No physical application/provider fixture was imported, executed
or built locally. Public Mypy/inventory fixtures were authored for hosted CI and are
not claimed as passed here.

GH107 remains open: selector implementation ownership, an origin-attested positive
collector, recursive dependency semantics, injection execution and parameter transfer,
and public product acceptance still need evidence.
