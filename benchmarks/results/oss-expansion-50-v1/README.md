# OSS expansion 50 v1

This artifact freezes the collection protocol and immutable PR identities for
50 additional OSS projects. It does not contain analyzer predictions or review
labels.

## Frozen artifacts

- Project manifest: `benchmarks/real_world/expansion/projects-50-v1.json`
  - SHA-256: `194afecc671535639cf51b4b98e6fbe2d36a6159c882de1ae2bd3a4df1a28fe0`
- Longlist and exclusions: `benchmarks/real_world/expansion/longlist-60-v1.json`
  - SHA-256: `271011f84984972c04cf3984a3e608399f3663c9ce493be9a12817968e63abe1`
- PR lock: `benchmarks/real_world/expansion/pr-lock-100-v1.json`
  - SHA-256: `6df3dc426888e0c8a97a079dbac8ca48ee421fa8ecd1ce63ddd7bf825a61291f`
- Exact collector source hash recorded by the lock:
  `633200e3c540ac7b38210f02eeac2f2b9db5814bc3848a5c2ec5ab439fa887a3`
- Independent exact-byte profile:
  `benchmarks/real_world/expansion/checksums-v1.json`

The lock contains exactly two PRs per project and records immutable base, head,
and merge commit SHAs. Every record starts with independent Review A, Review B,
adjudication, and PR-type fields in the `pending`/`unclassified` state. The
collector cannot manufacture completed reviews.

## Frozen selection

The population was frozen before expansion predictions. No analyzer output was
used for inclusion, exclusion, or partition assignment. Within each selected
repository, the collector chooses the two highest pull-request numbers among
merged PRs before `2026-06-15T00:00:00Z`. It never filters by title, changed
files, size, author, or predicted impact. Not-evaluable records must remain in
the corpus.

The longlist contains 50 selected and 10 excluded repositories with bounded
reason codes and human-readable rationales. The expansion is disjoint from Open
WebUI, Langflow, and Khoj.

## Diversity matrix

| Dimension | Frozen counts |
|---|---|
| Partition | verification 40; stress 10 |
| Size | small 15; medium 17; large 18 |
| Layout | package 34; monorepo 16 |
| Typing | mixed 43; strong 7 |
| HTTP/framework | HTTP 20; FastAPI 7; Starlette 2; Django 5; Flask 2; MCP 2; workers 10 |
| Reactive surfaces | tasks 10; RabbitMQ 2; Kafka 2; scheduler 1; CLI 3; event 1 |
| Effects | filesystem 50; SQL 4; Redis 3; HTTP 3; object storage 2; MongoDB 1 |
| License | Apache-2.0 22; MIT 19; BSD-3-Clause 8; LGPL-3.0 1 |

Presence in a project survey is not analyzer support and does not count as a
truth label. Framework, surface, effect, typing, and layout categories are
human survey labels tied to the listed survey commit; automated collection
verifies commit existence but does not prove those classifications.
Python-version and PR-type distributions remain review-time fields; they are
not inferred from repository names or analyzer behavior.

## Safety and reproducibility

Collection performs metadata-only HTTPS requests to `api.github.com`. It does
not clone, import, install, build, or execute upstream source. Redirects are
rejected so bearer credentials cannot cross origins. Per-response, aggregate
bytes, requests, pages, wall time, and local input sizes are bounded. Publication
uses an atomic no-clobber hard link.

The frozen run used 205 requests and 216,586,528 response bytes and produced
100 unique records. It verified all 50 survey commits and GitHub-reported SPDX
license fields. GitHub license metadata is an external
collection-time attestation, not a legal opinion or a commit-local license
proof.

Validate offline:

```bash
.venv/bin/python benchmarks/real_world/expansion_protocol.py --validate-only
.venv/bin/python benchmarks/real_world/expansion_protocol.py \
  --validate-lock benchmarks/real_world/expansion/pr-lock-100-v1.json
```

Live recollection is not an ordinary test and requires `GITHUB_TOKEN`. The
committed lock is immutable; the collector refuses to overwrite it. Offline
validation first authenticates the exact manifest, longlist, collector, and
lock bytes against `checksums-v1.json`, then validates every structural
invariant. A one-nibble identity mutation therefore fails before parsing.

## Remaining issue #103 work

Independent blind Review A/B, source adjudication, PR-type classification,
Python-version evidence, held-out evaluation, and stress evaluation are still
pending. These later phases must consume this lock unchanged and may not drop
not-evaluable PRs.
