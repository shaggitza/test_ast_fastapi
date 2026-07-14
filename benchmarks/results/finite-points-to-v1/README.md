# LOW-only finite points-to experiment v1

Issue: [#105](https://github.com/shaggitza/test_ast_fastapi/issues/105)

This experiment compares the merged `main` baseline `948a33d` with the Issue #105
implementation. Both analyzers used the same Python environment, immutable merge
snapshots, exact diffs, secure AST discovery, mypy, and `--no-cache`. No upstream
application code was imported or executed.

## Frozen cases

| Case | Parent | Merge | Config |
|---|---|---|---|
| Open WebUI #26911 | `0f8846b7fc8c210945366defbd1ed941b039a691` | `f4a6ea9300f130dc2f755d82d935f18160b8f5d2` | root `backend/open_webui` |
| Khoj #1292 | `e8631261400e0a04c5063e91e498b549976ffc53` | `530443a4f6ccd5281cefe8bbb82ab146fddf952b` | root `src/khoj`, app `main:app`, bootstrap `main:run` |

The Git objects came from the existing immutable `/tmp/current-corpus-cache`.

## Rollback gates

| Case | Baseline wall time | Candidate wall time | Change | Baseline candidates | Candidate candidates |
|---|---:|---:|---:|---:|---:|
| Open WebUI #26911 | 34.75 s | 32.48 s | -6.5% | 0 | 0 |
| Khoj #1292 | 14.72 s median (2 runs) | 12.41 s median (2 runs) | -15.7% | 1 LOW | 1 LOW |

Candidate identity was unchanged for both frozen cases. Khoj retained only
`POST /api/content/convert`; Open WebUI retained no candidates. Therefore the
holdouts added no false positives and passed the latency rollback gate.

The absence of a new Open WebUI candidate is intentional. `Vector.get_vector`
selects among more than the eight-target cap using runtime configuration, and the
async facade crosses `asyncio.to_thread`. The former remains unresolved rather
than partially fanning out; the latter belongs to executor summaries in #106.
Khoj's two configuration-dispatch routes remain unavailable in the established
inventory. The already-discovered direct convert route remains LOW.

## Recovered fixture semantics

Deterministic unit fixtures in `tests/unit/test_mypy_finite_points_to.py` prove:

- direct constructors and true local aliases;
- exact module-global constructors;
- finite project factory returns;
- constructor parameter to `self.field` delegation;
- exact concrete override dispatch and shared inherited declarations;
- LOW-only transitive provenance and cache round trips;
- eight-target, return-count, state, edge, call-depth, and cycle bounds;
- fail-closed conflicting overrides, global control flow, reflection, arbitrary
  member mutation, callback mutation, and target-cap overflow;
- preservation of exact `super()` reachability;
- stronger independent standard paths dominate LOW-only provenance.

## Reproduction shape

Materialize each immutable merge snapshot, create the exact parent-to-merge diff,
and run:

```bash
PYTHONPATH=<baseline-or-candidate>/src \
  <shared-python> fastapi-endpoint-detector analyze \
  --app <snapshot>/<configured-root> \
  --diff <parent-to-merge.diff> \
  --secure-ast --no-cache --format json
```

For Khoj, also pass `--app-entry main:app --bootstrap-entry main:run`.
Wall times above were captured with `/usr/bin/time` around the same shared Python
interpreter. The corpus runner was also executed for both cases; its separate
worktree/environment startup was not used for the paired latency comparison.
