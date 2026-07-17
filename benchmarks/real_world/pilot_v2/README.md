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

## Private cache and packet preparation

The cache/packet tool authenticates both frozen profiles before doing any work.
Caches are collision-resistant bare repositories containing exactly the two
locked shallow commit objects (deduplicated when equal), their trees/blobs, no
refs, and no other commit history. Validation is offline with lazy fetch,
alternates, replacement refs, partial/promisor objects, maintenance/gc, and
writable content forbidden. Packet snapshots are materialized directly from
strict `git ls-tree -rz --full-tree -r` identities and one bounded `git cat-file
--batch` stream per tree, so export attributes and substitutions cannot alter
bytes. Regular blobs become inert 0444 files; symlink target bytes and gitlinks
remain manifest-only metadata. The frozen remote diff hash/size and the local
Git diff hash/size remain explicit distinct fields.

Every validation requires the locked cache, holds private advisory locks across
cache validation and complete regeneration, verifies directory device/inode
stability, regenerates both snapshots and the local diff into a fresh bounded
temporary directory, and compares the exact semantic manifest and
domain-separated root. Process groups, CPU/address/file size/process counts,
wall time, output, staging disk, paths, modes, file counts, permissions,
inventories, and hashes fail closed. Preparation parents must be current-UID
0700 directories; published cache and packet trees are fully read-only. The
packet staging proof caps each snapshot at 256 MiB and each packet at 512 MiB:
three packets (1,536 MiB) plus one 260 MiB batch spool, 64 MiB tree listing, and
32 MiB diff total 1,892 MiB, below the 2 GiB aggregate cap. Cache staging is
capped at 8 GiB. Both phases preflight additional disk headroom and monitor the
whole staging root while subprocesses and blob copies run. Each cache is capped
at 2 GiB, so three complete caches consume at most 6 GiB and leave 2 GiB for
bounded fetch/index staging inside the 8 GiB aggregate ceiling. Validation
preflights 3 GiB so the published packet set and one bounded regenerated packet
can coexist. Advisory locks attest cooperating processes; the operator must
ensure no lock-ignoring process under the same UID mutates private roots during
validation. Payload inventories are re-read after regeneration to detect
in-window mutation. Caches and packets remain private and are never committed:

```bash
install -d -m 700 "$HOME/.cache/fastapi-endpoint-detector/pilot-v1-private"
.venv/bin/python -m benchmarks.real_world.pilot_packet_v2 \
  --prepare-cache \
  --cache-root "$HOME/.cache/fastapi-endpoint-detector/pilot-v1-private/cache"
.venv/bin/python -m benchmarks.real_world.pilot_packet_v2 \
  --validate-cache \
  --cache-root "$HOME/.cache/fastapi-endpoint-detector/pilot-v1-private/cache"
.venv/bin/python -m benchmarks.real_world.pilot_packet_v2 \
  --prepare-packets \
  --cache-root "$HOME/.cache/fastapi-endpoint-detector/pilot-v1-private/cache" \
  --packet-root "$HOME/.cache/fastapi-endpoint-detector/pilot-v1-private/packets"
.venv/bin/python -m benchmarks.real_world.pilot_packet_v2 \
  --validate-packets \
  --cache-root "$HOME/.cache/fastapi-endpoint-detector/pilot-v1-private/cache" \
  --packet-root "$HOME/.cache/fastapi-endpoint-detector/pilot-v1-private/packets"
```

## Private execution and custody foundation

After cache/packet validation, the supervisor freezes a strict private execution
manifest and initializes one append-only hash-chained custody stream per PR. The
human explicitly approved proceeding without a separate monetary hard cap; the
manifest retains the frozen 18-run/100,000-token limits and records their
protocol-derived worst-case ceiling of 54,000,000 micro-USD, plus the exact
approval text/hash/mode. This is not a claim that the ceiling will be spent.

```bash
AGENT="$HOME/.pi/agent/agents/benchmark-pilot.pilot-blind-reviewer-v1.md"
PRIVATE="$HOME/.cache/fastapi-endpoint-detector/pilot-v1-private"
NOW="2026-07-16T22:30:00Z"  # operator supplies the actual canonical UTC time
.venv/bin/python -m benchmarks.real_world.pilot_run_v2 \
  --freeze-execution --agent-config "$AGENT" \
  --cache-root "$PRIVATE/cache" --packet-root "$PRIVATE/packets" \
  --execution-root "$PRIVATE/execution" --occurred-at "$NOW"
.venv/bin/python -m benchmarks.real_world.pilot_run_v2 \
  --initialize-ledger --agent-config "$AGENT" \
  --manifest "$PRIVATE/execution/execution-manifest.json" \
  --cache-root "$PRIVATE/cache" --packet-root "$PRIVATE/packets" \
  --ledger "$PRIVATE/execution/custody.jsonl" --occurred-at "$NOW"
.venv/bin/python -m benchmarks.real_world.pilot_run_v2 \
  --write-review-a-tasks --agent-config "$AGENT" \
  --manifest "$PRIVATE/execution/execution-manifest.json" \
  --cache-root "$PRIVATE/cache" --packet-root "$PRIVATE/packets" \
  --task-root "$PRIVATE/execution/review-a-tasks"
```

The canonical custody ledger path is always derived from the authenticated
execution manifest. An optional CLI `--ledger` must resolve to that exact path;
shadow ledgers are rejected and all actions share its single lock namespace.
Task generation requires exactly the three initialized
`source_binding_frozen` events and refuses missing, advanced, or incident/no-go
ledgers. The custody CLI locks and validates the full ledger and execution
manifest plus complete private cache/packet regeneration before every task,
validation, or prospective append. Invalid order, broken hashes, retry
misbinding, added packet bytes, or any global no-go incident is rejected before
immutable bytes are appended. A crash can leave a partial append; this fails
closed as a corrupt/no-go custody stream and requires a new versioned execution,
never truncation, repair, or continuation.
Children never write custody. Reviewer task envelopes expose only the exact
packet/binding/policy/model/limit inputs and explicitly exclude predictions,
prior labels, Review B, and adjudications.

## Isolated parent Review B intervals (execution v3)

Execution v2 correctly failed closed before Review A escrow was opened because
one shared supervisor-session interval mixed all three PRs and orchestration.
Execution v3 also failed closed during its first active Review B interval because
Pi's unavoidable internal reasoning mentioned orchestration; its A escrow and B
artifact are quarantined and never canonical. Execution v4 uses
`pilot_review_b_v2.py` and exactly one active PR interval. The start command
authenticates manifest/cache/packets and clean A-started custody,
records the command-time session offset and fixed-scope allocated bytes, and
launches a private one-second supervisor-process-tree RSS sampler. Finish
requires exactly one successful leading tool result matching the stored start
call ID, making the retained boundary post-command, and excludes its own exact
single-executable-tool finish assistant message. The start and finish messages
may also contain any number of internal `thinking` items. Throughout the interval,
internal reasoning cannot access external data or execute activity, remains in the
raw hashed transcript and usage accounting, and is not treated as a data-access
surface. Visible text, images, unknown content, and a second boundary tool call
remain forbidden. Every retained tool call must have exactly one successful
matching tool result before another assistant/final boundary. Parent Review B is
independently authored and frozen before A is opened; it is not a clean-context
review lane.
Between start and finish, the parent may perform only assigned packet
`read`/`grep`/`find`/`ls` and exactly one bounded artifact-write `bash` command.
Finish rejects other PRs/paths/tools/network/orchestration, validates
strict lane-B artifact identity and policies, freezes exact session bytes,
provider usage, cost, RSS, disk, transcript, artifact, and boundary hashes, and
removes the active marker. A crash or contamination after marker publication
retains an incident-required marker; it is never repaired in place. A start
boundary that fails validation before marker publication cleans its private
staging directory and requires no incident.

```bash
# Before the isolated interval, generate and privately retain both canonical
# lines. ASSIGNED is deterministic OWNER--REPO--NUMBER.
.venv/bin/python -m benchmarks.real_world.pilot_review_b_v2 \
  --print-start-command \
  --manifest "$PRIVATE/execution-v3/execution-manifest.json" \
  --execution-root "$PRIVATE/execution-v3" --cache-root "$PRIVATE/cache" \
  --packet-root "$PRIVATE/packets" --agent-config "$AGENT" \
  --repository OWNER/REPO --pr NUMBER --supervisor-session "$SUPERVISOR_SESSION" \
  --supervisor-pid "$SUPERVISOR_PID" \
  --interval-root "$PRIVATE/execution-v3/review-b-intervals"
.venv/bin/python -m benchmarks.real_world.pilot_review_b_v2 \
  --print-finish-command \
  --manifest "$PRIVATE/execution-v3/execution-manifest.json" \
  --execution-root "$PRIVATE/execution-v3" --cache-root "$PRIVATE/cache" \
  --packet-root "$PRIVATE/packets" --agent-config "$AGENT" \
  --repository OWNER/REPO --pr NUMBER --supervisor-session "$SUPERVISOR_SESSION" \
  --interval-root "$PRIVATE/execution-v3/review-b-intervals" \
  --artifact "$PRIVATE/execution-v3/review-b-intervals/ASSIGNED/review-b.json"
# Copy the print-start helper's exact output line as the sole executable tool call.
# Its JSON result supplies assigned_root, boundary_sha256, and exact started_at.
# Parent reads only the assigned packet, then writes ReviewArtifactV1 once with
# run.started_at exactly equal to that started_at and completed_at no later than
# the later finish boundary. Copy the print-finish output as the sole executable
# tool call in the final assistant message. Optional internal thinking is allowed;
# never wrap either line in eval, a variable, cd/PYTHONPATH, prose, another tool,
# or a compound shell command.
```

## Remaining live phases

Supervisor must next launch Review A into unopened escrow, independently freeze
parent Review B with exact session boundaries, append custody/telemetry, then
open and validate A and run fresh adjudicators. Metrics and the objective go/no-go
report remain absent. Only after all gates and a separate post-pilot scale
approval may issues #149–#198 begin.
