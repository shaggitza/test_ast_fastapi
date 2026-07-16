# Benchmark v2 canonical ground truth

This repository-local package is the prediction-blind canonical store for issue
#146. It is deliberately outside the product wheel. The live database and a
public release remain blocked until issue #145 publishes the independently
authenticated 50x50-v2 lock.

## Custody and workflow

Only the parent benchmark process receives the database and invokes its writer
functions. Review A and Review B are immutable exact byte artifacts, imported
in one all-or-nothing batch after both lanes are frozen. Reviewers never receive
the database, one another's output, analyzer predictions, scores, route census,
or vendor output. Adjudication starts only after exact A/B hashes are present.
Every raw claim, terminal recommendation, structured unknown, and negative
assessment must be resolved exactly once by a typed decision source attributed
to `A`, `B`, `both`, or `newly_inspected`. Corrections append a version that
names its predecessor; SQLite triggers prohibit updates and deletes.

An empty claim set is not a negative label. Negative controls require a complete
changed-symbol census, searched entrypoint families, and explicit limitations.
`positive`, `negative_control`, `unknown`, and `not_evaluable` are separate
terminal states. The compatibility export maps only the first two to legacy
`status: adjudicated`, while preserving `terminal_status` on every PR.

## Corpus and evidence binding

Production initialization accepts the exact lock, manifest, and independent
checksum paths plus an offline tree resolver. It invokes
`expansion_protocol_v2.load_lock_authenticated` inside the initialization
boundary; a caller-supplied `CorpusDefinition` cannot assert production
authentication. A strict synthetic corpus is available only when
`allow_synthetic=True`; this is the offline unit-test path and cannot be silently
used for production.

Evidence is validated from collision-resistant local bare Git caches. The
validator checks the exact canonical GitHub remote, locked commit and tree,
regular blob identity, POSIX path, line range, dense connected chain, and that
the chain starts in a changed hunk. It sets `GIT_NO_LAZY_FETCH=1`, never creates
a worktree, never imports or executes source, and has command/blob/byte/line/wall
budgets. Missing objects fail closed; operators must prepare caches separately.

## Store and release invariants

- SQLite >=3.37, `STRICT` tables, foreign keys, immutable migration hashes, and
  append-only triggers are mandatory.
- Review imports contain exactly A and B for every selected PR. Adjudication
  imports contain exactly one record for every selected PR. Duplicate, partial,
  wrong-corpus, wrong-snapshot, and evidence-invalid batches roll back entirely.
- Raw artifacts are retained as exact BLOBs. Read-only validation re-hashes and
  reparses them, reconciles normalized rows, verifies ownership, and checks the
  live table/trigger digest against the migration bytes.
- Releases require a separately hashed affirmative human/agent publication
  review covering secrets, PII, and security findings. `manifest.json` is the
  commit marker and records corpus/schema/prompt hashes, denominators, canonical
  ordered per-table row counts and hashes, product-scope sidecars, exact file
  hashes, and a provenance-bound content root.
- Public exports contain an artifact hash index; raw notes remain in the private
  store unless a later publication policy explicitly permits them.
- A release directory is content-addressed and no-clobber. Later adjudications
  and releases cannot alter an earlier release.

The migration manifest hashes exact migration bytes. Never edit an applied
migration; append the next numbered SQL file and update the manifest before any
release using it.

## Bounded validation

```bash
.venv/bin/pytest -q tests/benchmarks/test_ground_truth_*.py
.venv/bin/ruff check benchmarks/real_world/ground_truth_v2 tests/benchmarks/test_ground_truth_*.py
.venv/bin/mypy benchmarks/real_world/ground_truth_v2
.venv/bin/python -m benchmarks.real_world.ground_truth_v2.store validate /path/to/private.sqlite
.venv/bin/python benchmarks/real_world/expansion_protocol_v2.py --validate-only
```

A real release additionally requires the #145 lock, complete review/adjudication
artifacts, offline caches for all evidence, publication approval, read-only
regeneration/hash comparison, and confirmation that all v1 sentinels remain
unchanged.
