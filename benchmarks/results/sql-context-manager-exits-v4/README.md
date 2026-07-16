# SQL context-manager exits v4

This phase adds exact, report-only SQLAlchemy transaction/savepoint context
exit evidence.

## Proven cases

- `with session.begin(): session.add(...)`
- `async with session.begin(): await session.add(...)`
- equivalent `begin_nested()` savepoint contexts
- exact schema-v2 user contracts with matching context-exit semantics

A transaction context records normal-exit commit reachability and
exceptional-exit rollback reachability. A savepoint context records normal-exit
release reachability and exceptional-exit rollback reachability. The outcome is
always conditional on context exit and persistence remains `not_established`.

## Fail-closed cases

Multiple context items, `as` captures, helper-mediated or control-flow-nested
stages, dynamic receivers, receiver reassignment, absent/mismatched contract
semantics, and source/index limits produce no context path. No method-name,
suffix, receiver-candidate, or generic context-manager matching is used.

## Invariants

Context paths are content-addressed and bound to the exact effect audit,
transaction report, endpoint, begin occurrence, stage occurrence, source file,
receiver hash, scope, and declared exit semantics. They are diagnostic-only and
cannot create/promote endpoint candidates, change thresholds, or claim runtime
transaction identity, successful commit/release/rollback, or durable writes.

The existing atomic pair cap includes potential begin-stage context pairs.
Controlled fixtures preserve candidate, affected-endpoint, and orphan
projections while proving transaction and savepoint contexts and rejecting an
`as`-captured context.
