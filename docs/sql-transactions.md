# SQL staging and transaction diagnostics

Select the package-owned SQLAlchemy contract table and opt in explicitly:

```yaml
analysis:
  effect_preset: sqlalchemy-v1
  sql_transaction_diagnostics: true
```

The execution-free analyzer recognizes exact SQLAlchemy 2.x `Session` and
`AsyncSession` staging and boundary methods. It reports endpoint-reachable:

- `add`, `add_all`, `delete`, and `merge` as `stage`;
- `flush` as a pending-persistence boundary;
- `begin` and `begin_nested` as transaction boundaries;
- `commit` and `rollback` as reachable outcome boundaries.

The report distinguishes `pending_persistence`, `commit_reachable`,
`rollback_reachable`, and `outcome_unresolved`. Every record retains
`persistence_status: not_established`. A reachable commit is not proof that it
runs after the staged call, succeeds, or durably persists that mutation. A
reachable rollback is likewise not proof that it controls the same transaction.
When commit and rollback are both reachable, the outcome is unresolved.

Diagnostics are report-only. They never create or promote endpoint candidates,
change confidence or thresholds, manufacture call stacks, or establish
changed-code causality. Exact symbol/invocation matching, established endpoint
inventory, secure AST discovery, and mypy call resolution remain mandatory.

## Bounded ordered-path diagnostics

A second explicit option adds strictly lexical stage-to-boundary evidence:

```yaml
analysis:
  effect_preset: sqlalchemy-v1
  sql_transaction_diagnostics: true
  sql_transaction_ordered_paths: true
  sql_transaction_path_max_pairs: 1024
```

An ordered path requires exact audited stage and commit/rollback occurrences in
the same source file, direct function body, and lexical order. Both calls must
use the same finite `Name`/`Attribute` receiver expression, with no intervening
assignment to that expression or one of its lexical ancestors. A nearest prior
same-receiver `begin` may be attached. Calls under branches, loops, `try`,
`with`, comprehensions, lambdas, nested scopes, dynamic receivers, mismatched
receivers, reversed boundaries, and reassigned receivers remain explicit
unresolved diagnostics.

The pair cap is checked atomically before source analysis. Exceeding it fails
explicitly without a partial report. Receiver hashes expose no source value and
prove spelling stability only—not alias, session, connection, or runtime
transaction identity. Ordered commit retains the `not_established` persistence
status because exceptions, runtime execution, commit success, and database
durability are outside this evidence.

## Conservative limits

Version 1 intentionally does not infer branch ordering, exception paths,
transaction identity, context-manager exit behavior, savepoint release,
autoflush, implicit commit, database durability, or ORM object/resource
identity. `execute()` and textual SQL are omitted because their read/write
semantics depend on the statement. Configured unit-of-work wrappers can be
modeled only with exact user effect contracts; spelling-based `commit`,
`rollback`, `flush`, or `add` matching is forbidden.
