# OSS expansion 50×50 v2 — frozen live corpus

This release freezes the preregistered 50-repository × 50-PR corpus: 50 complete
repository records and exactly 2,500 immutable PR identities. Selection and live
collection remain separate provenance layers; reviews, adjudications, labels,
and analyzer scores are still pending and are not claimed here.

## Frozen inputs

- Population: the exact 50 repositories in `oss-expansion-50-v1`
- V2 manifest: `benchmarks/real_world/expansion/projects-50x50-v2.json`
  - SHA-256: `abd4ee6418a70bf1963a379b26d3ddaf1fe43b2a5a5b60f4090801d1ac5dbc1c`
- V2 collector/validator: `benchmarks/real_world/expansion_protocol_v2.py`
  - SHA-256: `5ddbbf4a701b0e247c5b400cb8904709743291ce7637ed9d003f3d3a8c37a1d7`
- Independent preregistration profile:
  `benchmarks/real_world/expansion/checksums-50x50-v2-preregistered.json`
- Exact live lock: `benchmarks/real_world/expansion/pr-lock-2500-v2.json`
  - SHA-256: `70496533d84a3f97db24fd41acdde416d09a2f10787e2088f802769ad8e24552`
- Independent live checksum profile:
  `benchmarks/real_world/expansion/checksums-50x50-v2.json`
  - SHA-256: `94e535d1d54e951c0d893652f1b5a8df95aa406390fd169938b71157516436fe`

The preregistration remains byte-identical and still records
`live_lock_status: not_collected`; it is a historical pre-collection commitment,
not mutable status. The separate live profile authenticates exact manifest,
collector, and lock bytes without rewriting any preregistration or v1 artifact.

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
.venv/bin/python benchmarks/real_world/expansion_protocol_v2.py \
  --validate-lock benchmarks/real_world/expansion/pr-lock-2500-v2.json \
  --checksums benchmarks/real_world/expansion/checksums-50x50-v2.json
.venv/bin/python scripts/run_tests_bounded.py \
  tests/benchmarks/test_expansion_protocol_v2.py --pytest-arg=-x
```

The authenticated validator reports 50 projects and lock hash
`sha256:70496533d84a3f97db24fd41acdde416d09a2f10787e2088f802769ad8e24552`.
All repositories are `complete`, each has ranks 1–50, and all 2,500
case-insensitive repository/PR identities are unique. The collection consumed
8,108 requests, 284,550,321 response bytes, 76,738,081 diff bytes, and 8,756
seconds, all within frozen bounds.

Offline tests cover immutable v1 byte sentinels, fixed policy, merged-time and
PR tie ordering, shard gaps, proven underfill, unavailable separation, committed
2,500-row lock authentication, exact-byte tampering, diff bounds, no-clobber,
and credential-safe redirects.

## Remaining non-claims

Collection does not establish semantic ground truth. Every PR remains
`unclassified` with Review A, Review B, and adjudication `pending`. Issue #147
must pass the blind-review pilot before repository review issues #149–#198
begin. Analyzer predictions and final benchmark scores remain excluded until the
complete adjudicated truth release is frozen.
