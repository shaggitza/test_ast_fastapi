# Ground-truth production v1: offline foundation

This separately versioned profile freezes the issue-to-repository assignments and
offline scheduler genesis for reviews #149–#198. It does not reuse pilot custody
as production authority.

`assignments-v1.json` maps issue 149 to the first authenticated lock project,
issue 150 to the second, and so on through issue 198. The campaign builder calls
the existing expansion-v2 authenticated loader and accepts only one complete,
rank-ordered 50-PR repository slice. Each manifest contains exactly 100 planned
lane identities, with distinct lane-qualified reviewer names and versions.

The current authorization gates are deliberately false:

- `live_launch_authorized: false`;
- `source_packet_materialization_authorized: false`;
- `canonical_import_authorized: false`.

The campaign manifest alone authorizes none of those operations. Source cache and
packet materialization are separately layered milestones; model launch,
adjudication, and database import remain unavailable from the base manifest. Native
review authority can only be layered through the separately attested, expiring
rank-1 A/B canary protocol described below.

## Commands

All output and manifest paths must be absolute. Campaign and ledger state files
are published no-clobber as mode 0400 canonical JSON.

```console
python -m benchmarks.real_world.ground_truth_campaign_v1 build-manifest \
  --issue 149 --repository fastapi/full-stack-fastapi-template \
  --output /private/campaign-149.json
python -m benchmarks.real_world.ground_truth_campaign_v1 validate-manifest \
  --manifest /private/campaign-149.json
python -m benchmarks.real_world.ground_truth_campaign_v1 init-ledger \
  --manifest /private/campaign-149.json --ledger-root /private/ledger-149
python -m benchmarks.real_world.ground_truth_campaign_v1 validate-ledger \
  --ledger-root /private/ledger-149
```

The caller creates the ledger root in advance as an owned, non-symlinked,
absolute mode-0700 directory. Initialization serializes with `flock`, binds the
campaign file hash/device/inode, publishes exactly 100 `planned` states, and
creates a deterministic hash-chain genesis. It stores no capability or secret.
There are intentionally no state-transition or launch commands yet.

## Exact source cache milestone

`ground_truth_source_v1.py` authenticates one mode-0400 campaign manifest and
prepares a separate bare Git cache without touching pilot state. Production
transport is limited to full-SHA, depth-one, no-tag HTTPS fetches from the exact
`https://github.com/OWNER/REPOSITORY.git` remote. The runner uses argv arrays,
an isolated noninteractive Git environment, formula-derived 515-command preparation
and 313-command validation bounds at 100 commits, streaming aggregate output and
in-flight staging-disk enforcement with immediate process-group kill/reap, and no
credentials, hooks, checkout, worktree, archive, submodules, LFS, or lazy fetch.
Publication uses Linux `renameat2(RENAME_NOREPLACE)`, recursively read-only content,
and parent-directory fsync below a current-UID mode-0700 non-symlinked parent.

Offline validation requires the exact sorted, duplicate-free baseline/target shallow
boundary, no refs or `FETCH_HEAD`, exact object closure with no unreachable extra
objects, exact local configuration, and no replacement/alternate/promisor/partial
state. It computes a complete deterministic inventory over every descendant
path/type/mode/size/file SHA before and after all Git checks. Source bindings freeze
that inventory root, counts, disk bytes, cache device/inode, all 50 commit/tree
identities, and all diff identities; binding publication repeats the inventory on
both sides of publication so descendant drift cannot enter an accepted binding.
They keep packet, review, live-launch, and canonical-import gates false.

```console
python -m benchmarks.real_world.ground_truth_source_v1 prepare-cache \
  --campaign /private/campaign-149.json --cache /private/source-149.git
python -m benchmarks.real_world.ground_truth_source_v1 validate-cache \
  --campaign /private/campaign-149.json --cache /private/source-149.git
python -m benchmarks.real_world.ground_truth_source_v1 build-source-bindings \
  --campaign /private/campaign-149.json --cache /private/source-149.git \
  --output /private/source-bindings-149.json
python -m benchmarks.real_world.ground_truth_source_v1 validate-source-bindings \
  --campaign /private/campaign-149.json --cache /private/source-149.git \
  --bindings /private/source-bindings-149.json
```

## Layered packet materialization

The immutable campaign and source-binding packet gates remain false. Packet
materialization requires a separate expiring, hash-chained
`PacketMaterializationAuthorizationV1` ledger transition. It binds the exact
campaign, source bindings, cache inventory/device/inode, production checksum
profile, private output parent identity and absent basename, and fixed limits. It
grants packet materialization only; live launch and canonical import remain false.

`checksums-packet-v1.json` permanently authorizes every production-v1 packet
generation. The evolving `checksums-v1.json` authenticates that frozen file and the
current compatibility module. Authorization and receipt validation select the frozen
packet profile by its exact profile hash, so later submit/runtime growth cannot stale
immutable packets. Every packet policy, schema, and low-level dependency retains its
frozen digest; only the old packet-module self-digest is non-authoritative because
current `checksums-v1.json` authenticates that executable module. Unknown or edited
phase profiles fail closed.

Authorization is single-use. Every fallible source, cache, profile, output-parent,
and inventory check completes before its durable ledger append. Build requires that
unused authorization as the current head. Each Git command receives a fresh
180-second deadline inside the six-hour aggregate deadline, while an independent
250-command counter covers each build or regeneration pass.

Publication is one same-parent aggregate `RENAME_NOREPLACE`. Immediately afterward,
a monotonic `packet-materialization-publication-v1` successor consumes the
authorization and binds output device/inode, aggregate manifest/root, complete
inventory, payload totals, and the actual final-boundary timestamp. A crash between
rename and ledger append is recovered only with `finalize-packets`, which fully
regenerates and authenticates the existing output before appending that exact
successor. Validation requires the successor; it may run after authorization expiry
only when the bound publication timestamp was within the original interval. Each of
the 50 reviewer packets exposes only baseline/target regular files, a locally generated
`snapshot.diff`, source-structure metadata for omitted symlinks/gitlinks, its
manifest, and checksum-authenticated packet policy/schema. The remote diff hash and
size remain metadata with `payload_present: false`; the local relation is always
`not_compared`. Full campaign/runtime and final-audit validation regenerates all 50
packets from the exact cache. Per-attempt preparation and broker recovery still verify
every aggregate packet hash, mode, ordering, root, payload total, publication successor,
and complete aggregate/cache inventory, but regenerate only the exact bound rank using
five Git commands. Pilot-v2 bytes are a checksum-bound low-level parser/materializer
dependency and are neither modified nor used for production authorization, custody, or
publication.

```console
python -m benchmarks.real_world.ground_truth_packet_v1 authorize-packets \
  --campaign /private/campaign-149.json --bindings /private/source-bindings-149.json \
  --cache /private/source-149.git --ledger-root /private/ledger-149 \
  --output-root /private/packets-149
python -m benchmarks.real_world.ground_truth_packet_v1 build-packets \
  --campaign /private/campaign-149.json --bindings /private/source-bindings-149.json \
  --cache /private/source-149.git --ledger-root /private/ledger-149 \
  --output /private/packets-149
# Recovery only when atomic publication succeeded but its successor append did not:
python -m benchmarks.real_world.ground_truth_packet_v1 finalize-packets \
  --campaign /private/campaign-149.json --bindings /private/source-bindings-149.json \
  --cache /private/source-149.git --ledger-root /private/ledger-149 \
  --output /private/packets-149
python -m benchmarks.real_world.ground_truth_packet_v1 validate-packets \
  --campaign /private/campaign-149.json --bindings /private/source-bindings-149.json \
  --cache /private/source-149.git --ledger-root /private/ledger-149 \
  --output /private/packets-149
```

## Typed submission broker milestone

`ground_truth_submit_v1.py` prepares one supervisor-owned, lane-qualified binding
from an authenticated published packet and exposes the local Unix-socket semantic
submission broker. The reviewer sees only the immutable packet and review policies;
canonical corpus/reviewer identity, commits, trees, blob IDs, evidence ordinals, and
escrow paths remain supervisor-owned. Expected draft/evidence errors are correctable
for at most three calls. Accepted escrow is mode 0400 and requires the exact
nonsemantic `SUBMISSION_COMPLETE` acknowledgement.

This milestone does **not** add a scheduler, native agent, launch plan, session audit,
live-review authorization, adjudication, or canonical import. All such gates remain
false. The extension is stored inertly below `production_v1/extensions` and may only
be copied into a future hash-bound child runtime; it is not a parent project extension.
It uses only `/tmp/ground-truth-review-v1-UID` registry descriptors and does not accept
environment-based transport bindings. Binding preparation captures the authenticated
production checksum profile and every policy byte once, copies only that snapshot,
and reauthenticates the exact profile/source/cache/packet boundary before no-clobber
publication. Recovery creates a fresh exact-cache evidence validator between fresh
custody authentications. Cleanup removes only publication links whose device/inode
still matches the link created by that invocation, so a raced-in file is never unlinked.

## Native runtime and rank-1 A/B canary

`ground_truth_run_v1.py` authenticates the complete production custody chain and
pins `pi-subagents` 0.35.1, Pi 0.80.10, resolver/package/config bytes, the resolver's
builtin/package/user/project/effective census, discovery roots, and fork-only/off
intercom. Attestation copies the submit extension only into a private execution root
and appends a no-launch ledger successor. A unique mode-0400 Luna-medium agent must
then be installed at the exact flat user path
`~/.pi/agent/agents/ground-truth-production-reviewer-v1.md`; resolver collisions,
hash drift, wrong tools/model/thinking, or a different effective agent fail closed.

Before any review authorization or lane event exists, one operational recovery may
append `runtime-attestation-supersession-001.json` on a new absent execution root.
It must name and immediately follow the immutable initial attestation, becomes the
only current runtime head, and still grants no review launch, adjudication, or import.
A second supersession or any supersession after authorization/activity fails closed.

Only the exact rank-1 A/B campaign lanes can receive the initial expiring canary
authorization. Their ordered lane keys, attempt IDs, and reviewer identities are hashed
into the runtime attestation and must match the authorization byte-for-byte. Each lane
is single-process and nonreplaceable. Preparation repeatedly reauthenticates the full
runtime/installation/ledger tuple under the ledger lock before binding publication,
broker spawn, and the prepared event; drift fails closed and cleans the attempt.
Preparation also enforces three global durable active slots, writes the inode-keyed
private registry descriptor, and starts only the resource-bounded local broker.
`native-launch-plan` validates the complete call against pinned Pi 0.35.1
`SubagentParams` before atomically recording the ordered attempt/task-index mapping in
one batch `launch_claimed` successor and emitting data for the supervisor's native
`subagent(...)` tool. Python never launches Pi, a model, or a provider. A lost plan
remains claimed and cannot be relaunched.

`bind-native-result` freezes one native run ID per batch and requires each child session
at the exact authenticated Pi layout
`<sessions>/<parent-session>/<native-run-id>/run-<task-index>/session.jsonl`, with a
start timestamp no earlier than the batch claim. It binds parent status and immutable
child session identity before escrow finalization. Parent failure
becomes monotonic `operational_failed`. Eligibility requires that prior success
binding, exact chained Pi v3 session grammar with unique event IDs and a linear
parent-ID chain, one byte-exact initial task with no steering, Luna-medium identity,
packet-confined tools, one-to-three nonerror
submissions, final `SUBMISSION_COMPLETE`, integer usage/micro-USD, and fresh
escrow/evidence recovery. Reconciliation scans every durable slot, including claims
that failed before a lane event; claimed launches are never relaunched. Adjudication
and canonical import remain false.
