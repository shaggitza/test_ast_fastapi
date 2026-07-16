# SQL transaction scopes v3

This phase adds exact declared transaction/savepoint scope without inferring
runtime transaction identity or context-manager outcomes.

## Contract semantics

Effect-contract schema v2 adds `behavior.transaction_scope` only for SQL
`begin` operations with `context_enter` timing. The SQLAlchemy preset now marks:

- `Session.begin` and `AsyncSession.begin` as `transaction`;
- `Session.begin_nested` and `AsyncSession.begin_nested` as `savepoint`.

Schema-v1 and unclassified user begin contracts remain explicit `none`. No
method-name, suffix, or source-spelling fallback is used.

## Evidence

SQL transaction and ordered-path report schemas advance to v2. Endpoint
diagnostics retain one sorted scope record for every exact reachable begin
occurrence. Same-scope straight-line ordered paths copy the
scope of their nearest prior same-receiver begin. Report validation checks that
the scope agrees with the exact effect audit and endpoint evidence.

A controlled fixture covers transaction and savepoint begin calls followed by
stage and commit. Both remain `not_established`: savepoint release, context
exit, exceptions, commit success, durability, aliases, and runtime session
identity are not inferred. Candidate projections and confidence remain
unchanged.

## Validation

Focused strict mypy, Ruff, preset snapshot, model tamper, ordered-path, and
integration tests pass in isolated processes. Broader context-manager exit and
configured wrapper execution fixtures remain open under Issue #99.
