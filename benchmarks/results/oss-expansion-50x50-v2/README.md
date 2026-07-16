# OSS expansion 50×50 v2 — preregistered collection protocol

This phase preregisters the immutable selection, provenance, safety, and output
schema for the requested 50-repository × 50-PR corpus. It does **not** claim that
the live 2,500-PR lock has been collected.

## Frozen inputs

- Population: the exact 50 repositories in `oss-expansion-50-v1`
- V2 manifest: `benchmarks/real_world/expansion/projects-50x50-v2.json`
  - SHA-256: `abd4ee6418a70bf1963a379b26d3ddaf1fe43b2a5a5b60f4090801d1ac5dbc1c`
- V2 collector/validator: `benchmarks/real_world/expansion_protocol_v2.py`
  - SHA-256: `93952998c0087d66b17622c95ea4b77c5796efa7a3ea1ce8584415b66d5d4ad6`
- Independent preregistration profile:
  `benchmarks/real_world/expansion/checksums-50x50-v2-preregistered.json`

The profile explicitly records `live_lock_status: not_collected` and a null lock
hash. A later live collection must publish a separate exact-byte checksum
profile; it must not rewrite this preregistration or any v1 artifact.

## Selection

For every repository, the target is the latest 50 eligible merges strictly
before `2026-06-15T00:00:00Z`, ordered by:

1. `merged_at` descending;
2. PR number descending as the deterministic tie-break.

Selection may consume only complete, contiguous, newest-first merged-time
shards. Dense shards must be split. Cross-shard duplicates are joined only by
exact PR number and conflicting identities fail closed. Underfill is valid only
when complete coverage reaches the repository creation time. API, budget,
redirect, dense-shard, immutable-identity, and diff failures are `unavailable`,
never fabricated underfill.

No title, author, files, size, source behavior, analyzer result, route census,
or predicted impact may affect selection. Docs, generated, bot-authored, revert,
merge-queue, unsupported, unknown, and not-evaluable PRs remain eligible. A
merged PR remains eligible regardless of prior draft history. Renamed,
transferred, deleted, inaccessible, or redirecting repositories are terminal
`unavailable`; they are never followed or substituted after freeze.

## Locked identity schema

Every terminal selected record must bind:

- selection rank, PR number, canonical URL, and exact merge timestamp;
- base, head, and merge-commit SHAs;
- all merge-parent SHAs;
- baseline as the merge commit's first parent;
- target as the PR head SHA;
- SHA-256 and byte count of the exact streamed GitHub `.diff` representation;
- pending Review A/B/adjudication and unclassified PR-type state.

The offline validator requires all 50 repositories in manifest order and exactly
50 records for `complete`. `underfilled` requires proven full-history coverage.
`unavailable` retains a structured terminal reason and diagnostics. A final lock
is authenticated against an independent manifest/collector/lock checksum
profile before JSON parsing.

## Safety and bounds

The protocol forbids importing, installing, building, testing, hooking,
submodule/LFS processing, containers, and upstream-code execution. Inputs are
untrusted data. API requests may target only HTTPS GitHub hosts. API redirects
are rejected; diff redirects are restricted to GitHub's diff host and strip
authorization, cookie, and proxy credentials.

The manifest freezes request, response, per-diff, aggregate-diff, wall-clock,
timeout, rate-limit retry/wait, page, shard, candidate, checkpoint, file-count,
diagnostic, and final-output limits. Diffs are streamed into SHA-256 and are not
retained in memory. Complete search shards fit one response, preventing mixed
pagination snapshots. Publication is atomic and no-clobber. Live collection
uses strictly validated, content-hashed atomic per-repository checkpoints and
resumes under one aggregate request/byte/wall budget without repeating completed
repositories. It must run as a dedicated bounded collection, not as an ordinary
test.

## Validation

```bash
.venv/bin/python benchmarks/real_world/expansion_protocol_v2.py --validate-only
.venv/bin/python scripts/run_tests_bounded.py \
  tests/benchmarks/test_expansion_protocol_v2.py --pytest-arg=-x
```

Offline tests cover immutable v1 byte sentinels, fixed policy, merged-time and
PR tie ordering, shard gaps, proven underfill, unavailable separation, 2,500-row
lock validation, exact-byte authentication, one-nibble tampering, diff bounds,
and credential-safe redirects.

## Remaining live gate

No live 2,500-PR collection was run in this phase. The allowlisted GitHub
shard/detail/diff transport and resumable per-repository checkpoints are covered
by fake-transport tests, but still require the dedicated live run under frozen
aggregate limits. Issue #145 must remain open until a complete or explicitly
terminal result exists for all 50 repositories and the final lock/checksum
profile is committed and validated.
