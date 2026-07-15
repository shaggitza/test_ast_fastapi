# SQL transaction semantics v1

This phase freezes conservative report-only staging and boundary evidence for
SQLAlchemy 2.x `Session` and `AsyncSession`.

## Controlled fixture

Four established FastAPI endpoints exercise:

1. staging without a reachable outcome (`pending_persistence`);
2. begin, stage, flush, and commit (`commit_reachable`);
3. stage and rollback (`rollback_reachable`);
4. stage with both commit and rollback (`outcome_unresolved`).

The configured and unconfigured candidate projections, affected endpoints, and
orphan accounting remain identical. Every outcome keeps persistence
`not_established`; no durable-write claim is emitted. Tampered endpoint and
occurrence evidence fails report validation. JSON/YAML and text/Markdown/HTML
outputs preserve the diagnostic-only boundary.

## Validation

Tests run in isolated per-file pytest processes to avoid accumulation of mypy
semantic graphs. The SQL integration fixture passed with peak RSS below 0.85 GiB.
Focused strict mypy, Ruff, formatting, preset hash, and diff checks accompany the
fixture.

## Deferred

Source-proven control-flow ordering, exception paths, context-manager exit,
transaction/session identity, savepoint outcomes, configured wrapper summaries,
resource coupling, removed boundaries, and independently adjudicated real-PR
fixtures remain required before Issue #99 can close.
