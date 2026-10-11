# GH107 direct mapper diagnostic R7

Date: 2026-10-11 UTC
Branch: `codex/gh107-direct-mapper-r7-20261011`
Base: approved R6 commit `760963fba6722b59a5b3a44c2815136fda59d6c9`

## Bounded result

R6 already supplied the retained ordinary-build bridge, exact handler binding,
changed-coordinate seeds, and separate opt-in target/baseline graph queries. This
change uses that integration and adds a private per-side comparison record after
the authoritative mapper candidates have been materialized. Each record carries
physical occurrence IDs, endpoint IDs, and direct edge witness IDs with exact
caller and changed-seed source coordinates. The Git rename fixture exposed that
removed-line shadow seeds used the target path (`DiffFile.path`) instead of the
source path (`DiffFile.source_path`); baseline line mapping now uses the
source-side path. It compares endpoint IDs descriptively with the combined
legacy candidate set and states that the legacy set is not side-separated and is
not a parity oracle. Duplicate route occurrences remain distinct in the physical
occurrence list. Comparison exceptions clear only this private diagnostic; they
cannot change the report. `typed_graph_shadow` remains opt-in and default false.

Direct evidence rows are emitted only for a proven graph edge connecting the
bound handler symbol to the changed seed symbol. Unresolved uncertainty remains
in the graph query as LOW evidence; comparison does not convert it to proven
impact or remove it to match legacy output.

## Original acceptance checklist and current boundary

Original source: `/tmp/gh107-original-issue-20261011.json`.

| Original criterion | State after R7 |
|---|---|
| Symbol/edge IR with occurrence provenance | Existing PR336 graph plus retained bridge; R7 records duplicate physical route occurrence IDs. |
| Target-added and baseline-removed seeds | Existing side-specific line seeding; public fixture asserts both side queries and exact route-call spans. |
| Reverse SCC-safe traversal and multiple paths | Existing graph core and tests unchanged. |
| Handler occurrence mapping | Existing exact bridge; R7 verifies two stacked route registrations remain two occurrences. |
| Parity oracle against current full-depth output | Not established. R7 comparison is diagnostic only, and the public legacy candidate list is combined across sides. |
| Graph cache provenance | Existing provenance validation remains in place; this change adds no persistent graph cache. |
| No candidate/evidence loss on corpus and adversarial fixtures | Not established. Deferred, DI, Any/open protocol/member-dispatch, and effect uncertainty remain explicit LOW/unknown. No corpus run is claimed. |
| Performance gate and rollback | Not established. This does not promote graph output or alter the legacy report path. |

The current acceptance audit `/tmp/gh107-current-acceptance-audit-20261011.md`
identified the absent public mapper caller. R6 approved only opt-in, private,
LOW/default-false diagnostics over the retained authenticated build and specified
this direct-call mapper gap. R7 does not extend approval to output authority.

## Prior findings and responses retained

- R1 retained-build review: source, mypy state, options, and provenance must match
  before graph construction. R7 continues to call `build_shadow_graph`, which
  authenticates the retained `BuildResult`; it introduces no independent build.
- R2 harness (`/tmp/gh107-shadow-parity-research-r2-20261011.py` and
  `/tmp/gh107-shadow-parity-research-r2-20261011/case-record.json`): candidate
  differences included dead/deferred, DI, member/constructor, and Any routes;
  legacy candidates were not side-separated. R7 keeps the comparison disclaimer
  and preserves all query uncertainty.
- R3 isolation review: shadow must be default-disabled, private, and isolated
  from ordinary mapper exceptions. R7 leaves the constructor default unchanged;
  graph and descriptive-comparison ordinary exceptions clear shadow state only.
  `BaseException` still propagates because the guard catches `Exception` only.
- R4 execution repair: dead branches, default ownership, async/generator state,
  decorator/control-flow uncertainty, and narrowest changed-symbol seeding were
  repaired in the approved base and remain unchanged.
- R5 was implementer-authored and is not treated as independent approval.
- R6 independent review approved the exact base `760963f...` for shadow-only
  diagnostics and identified the next direct-call public mapper increment. R7
  stays within that boundary.

The R4 full harness record is
`/tmp/gh107-shadow-parity-repair-r4-20261011/case-record.json`. It separately
records baseline `common.shared_v1` and target `common.shared_v2` seeds, direct
executed `/two` evidence, LOW unknown `/deferred` evidence, and explicit Any,
Depends, and member-target uncertainty. It reports candidate mismatches rather
than scoring legacy as truth. R7 does not reinterpret these observations.

## Fixture and verification

The public mapper regression uses static source only. Baseline and target trees
change a helper return line; the target handler has two stacked route decorators.
The test invokes opt-in public `ChangeMapper.analyze_diff`, checks separate
baseline/target graph results, two route occurrence identities per side, direct
edge witness coordinates at the handler call (line 6, columns 29–37), and the
non-oracle comparison label. A second fixture commits static sources, archives
the baseline, renames `routes.py` to `handlers.py`, and sends the actual
`git diff --cached --find-renames` through the public mapper. It checks two
route occurrences and side-specific changed-seed modules. No source application
code is imported or run.
Existing graph tests cover unresolved virtual/member dispatch, DI, deferred
coroutine state, dead-branch suppression, changed-coordinate seeds, and
baseline/target snapshot separation.

Python commands used the locked Python 3.11.16 at
`/tmp/pr341-ci-host-locked-20261010/bin/python`, with candidate-only `PYTHONPATH`
pointing at `/tmp/test-ast-gh107-direct-mapper-r7-20261011/src` and that worktree.
Ruff 0.17.0 was run from isolated `/tmp/gh107-ruff-017-20261011/bin/ruff`:

- Ruff **0.17** check and format check on the two changed source files and bridge
  test: pass.
- Mypy on `typed_reverse_graph.py`, `typed_graph_bridge.py`, `change_mapper.py`,
  and `mypy_analyzer.py`: pass, four files.
- Import guard: printed and asserted `typed_reverse_graph.__file__` is inside the
  R7 worktree `src/`.
- Public mapper baseline/target duplicate-occurrence/direct-edge test and actual
  Git rename fixture: pass.
- Deferred coroutine/dead-branch and virtual dispatch/effect uncertainty graph
  regressions: pass.
- `git diff --check`: pass before commit.

No VM, application corpus, app/package execution, GitHub write, push, model, key,
broker, or SDK service was used. The shared original worktree was not modified.

## Scope limits

The mapper report remains the only authority. R7 does not establish full
baseline/target lifecycle parity, rename parity, complete occurrence-to-legacy
matching when endpoint identifiers collide, DI or open-protocol transfer,
finite virtual/member dispatch, deferred callable/effect semantics, corpus
no-loss, persistent cache reuse, a production performance threshold, or rollback
acceptance. GH107 remains open.
