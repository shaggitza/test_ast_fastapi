# Blind review/adjudication pilot v1

This directory freezes issue #147 protocol inputs and authenticated immutable
source bindings for three pilot PRs. It does **not** claim an execution manifest,
reviews, adjudications, metrics, or a passed gate.

## Fresh content-blind selection

The exact authenticated 2,500-PR lock supplies project order, selected identities,
and complete `selection_evidence` candidate identity/timestamp data. Exact hashes
of historical Review A, Review B, and adjudicated JSONL form a prior-label
exclusion set. In lock order, selection excludes each project's 50 records and
all prior labels, chooses the newest remaining `(merged_at, PR number)` candidate,
and takes the first three eligible projects. No title, author, body, file, size,
source, label, prediction, or analyzer result participates; no substitution is
allowed after freeze.

Frozen fresh identities:

- `fastapi/full-stack-fastapi-template#2164`
- `Kludex/starlette#3257`
- `PrefectHQ/prefect#22189`

They have zero overlap with the 2,500 evaluation identities and exact historical
label identities. They are protocol records only and never enter evaluation
truth or scores. Three records cannot estimate population accuracy.

## Frozen artifacts

- review/adjudication prompts define schema-supported output and external
  supervisor-owned provenance;
- model/tool/source/scope policies freeze blindness, a custom fresh
  `inheritProjectContext: false` agent with exactly `read/grep/find/ls`, isolated
  read-only source packets, no child writes/network/execution, and concrete
  `fastapi-adapter-v1` classification (source-established canonical HTTP is in
  scope; every other schema kind is out of scope);
- `custody-contract-v1.json` freezes canonical append-only no-clobber event
  chaining, escrow order, attempts, retries, hashes, and incidents;
- `telemetry-contract-v1.json` freezes two exact lifecycle sources: pi-subagents
  0.34.0 status/events for Review A/adjudication and a unique isolated
  supervisor-session start/end event+message interval for parent-written Review
  B. Every attempt requires wall, tokens, tools, bytes, one-second RSS, disk,
  retry/failure, transcript, and integer micro-USD cost telemetry for GO;
- `metrics-spec-v1.json` freezes exact attempt/stream populations, quantiles,
  claim-set/Jaccard denominators, integer retry/failure operands, conservative
  2,500-PR token/byte/wall/cost/RAM/disk/concurrency projections, and separate
  pre-pilot versus post-pilot scale approvals;
- `execution-manifest-schema-v1.json` freezes required execution/model/client,
  integer micro-USD-per-million-token pricing and budget, Review B interval
  measurement, agent, policy, source packet, and scope bindings;
- `checksums-v1.json` independently hashes every frozen policy/prompt/contract.

## Offline authentication

From repository root:

```bash
.venv/bin/python benchmarks/real_world/pilot_protocol_v2.py
.venv/bin/python scripts/run_tests_bounded.py \
  tests/benchmarks/test_pilot_protocol_v2.py --pytest-arg=-x
```

The validator bounds reads; rejects duplicate keys, excessive nesting, NaN and
Infinity; authenticates exact bytes before parsing; consumes authenticated
policy bytes without reopening them; reproduces selection; verifies all frozen
hashes; and proves zero evaluation/prior-label overlap. It performs no network
access and never imports or executes upstream source.

## Live source-binding phase

The bounded collector authenticates this preregistration before requesting only
the three frozen PR identities. It records initial and post-diff confirmation
pull responses, merge-commit, baseline, target, and exact streamed diff
provenance without cloning, extracting, importing, or executing source. The
frozen protocol requires at least 21 actual HTTP transactions: five API
responses plus the exact GitHub-to-patch redirect transaction pair per PR.
Redirect bodies are bounded and counted, and any identity change during diff
streaming fails closed:

```bash
GITHUB_TOKEN=... .venv/bin/python -m benchmarks.real_world.pilot_source_v2 \
  --collect \
  --output benchmarks/real_world/pilot_v2/source-bindings-v1.json
```

Publication is atomic and no-clobber. The completed binding contains all three
records and consumed 21 actual HTTP transactions, 185,259 response bytes,
11,792 diff bytes, and 12 conservatively rounded seconds. Exact frozen hashes:

- source collector: `8d3c1d60d7030e027987d9203f021e664a23b221c8bbbe4721c19c237880866d`;
- source bindings: `5a7b5b29bf23f6f0a03e048df56bef50e34bf8718cc4777617be6d9a87c97d9d`;
- independent binding profile: `b04cdfc58d0326a58099d69ebc2710d53ff682a97f8bf925d039f13cab3eed47`.

The independent `source-bindings-checksums-v1.json` authenticates exact
preregistration-profile, collector, and source-binding bytes. Authentication
runs offline:

```bash
.venv/bin/python -m benchmarks.real_world.pilot_source_v2 \
  --validate benchmarks/real_world/pilot_v2/source-bindings-v1.json \
  --checksums benchmarks/real_world/pilot_v2/source-bindings-checksums-v1.json
```

Neither file may claim reviews, adjudications, metrics, or a passed gate.

## Remaining live phases

Supervisor must next prepare bare caches, isolated read-only packets, custom
agent config, execution manifest, ledger, telemetry sampler, and metric reducer,
all under frozen contracts. For each PR, Review A runs into unopened escrow;
parent freezes Review B; then A is opened/validated and a fresh adjudicator runs.
Only after all objective gates and a separate post-pilot scale approval may
issues #149–#198 begin.
