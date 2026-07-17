# Blind review typed-submission pilot v3

This is a new protocol profile for issue #217. It does not modify or retroactively
claim compliance with pilot v1/v2 executions.

The provider-facing `submit_blind_review` tool accepts only a small semantic
`ReviewDraft`: terminal outcome, changed-symbol names and source ranges, claims
and source ranges, structured unknowns, negative assessment, and notes. The
model never supplies corpus/repository/PR/lane, reviewer identity, policy hashes,
resource limits, lifecycle timestamps, commit or blob hashes, IDs, evidence
ordinals, a socket, cache, binding, or output path.

A supervisor-owned one-attempt broker:

1. binds the real packet cwd/device/inode, private capability, exact lane, and
   no-clobber escrow destination;
2. authenticates the packet manifest, complete packet payload, prompt and
   policies at binding load and again for submission/recovery;
3. reconciles the manifest semantic root and a domain-separated side/path/blob
   inventory digest;
4. deterministically injects every trusted artifact field, source commit/blob,
   generated ID, and dense evidence ordinal;
5. validates strict Pydantic terminal semantics and immutable Git evidence;
6. atomically publishes canonical mode-0400 artifact and receipt sidecar;
7. fully reauthenticates and revalidates before returning a deterministic summary.

A lost success response is idempotently recoverable only when the exact artifact,
receipt sidecar, binding hash, immutable inputs, and Git evidence all revalidate.
An incomplete or altered escrow fails closed. The model never writes a file;
`submit_blind_review` is only a Unix-socket client to the supervisor broker.

## Phase status

Phase 1 implements the Python broker, semantic TypeBox client, deterministic
receipt/summary, strict security tests, a real offline Git-evidence integration
test, and static extension/schema contract checks. It performs no live model run,
changes no canonical database, and does **not** claim extension loading or child
propagation has been proved.

Phase 2 adds `pilot_typed_run_v3.py`. It prepares new read-only v3 packets from
fully validated v2 packets without mutating them, adds the frozen v3 policies,
and creates a distinct immutable packet cwd and one-attempt broker binding per
lane. Python never launches a review model. `prepare-native-attempt` starts only
the deterministic broker and publishes a secret-free launch receipt. At execution
creation it also copies the TypeScript extension, semantic schema, prompt, and
profile into an immutable execution-owned runtime, then hash-binds the generated
agent bytes to those copies. Installation is accepted only inside Pi's recursive
user-agent discovery root. The installer and every launch invoke the exact pinned
pi-subagents 0.34.0 resolver and bind its module/package bytes, effective result,
and builtin/package/user/project candidates. This covers project `.pi/agents`,
project and user legacy `.agents`, the exact `getAgentDir()` location including
`PI_CODING_AGENT_DIR`, configured and installed package agent roots, and global
package discovery. They require exactly one matching runtime name at the
receipt-bound real path and reject changed census bytes, collisions, symlinks,
and unscanned extra roots. The
parent must launch every review through the native `subagent(...)` tool using
`native-launch-plan.subagent_call`, fresh context,
concurrency three, and disabled artifacts/output/progress. The plan reauthenticates
the execution runtime, agent, complete packet/policies, binding, registry, live
broker, and remaining absolute deadline immediately before it emits tasks.

Because the native subagent API has no per-task environment, the child-only
extension looks up a mode-0600 descriptor keyed by the exact cwd device/inode in
a mode-0700 `/tmp/pilot-review-v3-UID/registry`. It authenticates owner, modes,
paths, cwd identity, socket and capability. The broker additionally verifies the
Unix peer PID/UID and `/proc/PID/cwd` device/inode. Descriptors remain outside
packet payloads and are never model-selectable.

`finalize-native-attempt` ignores model prose, independently recovers and
reauthenticates escrow with immutable Git evidence, requires successful broker
status, publishes a no-clobber terminal result, then removes socket/registry and
releases its durable lease. Failure publishes a separate terminal marker and
cleans capabilities. Finalization is serialized by a per-attempt flock; repeated
finalization reauthenticates the already published result, and success/failure
markers cannot both be published. At most three durable leases may be active.
Preparation leases immediately record process identity and state location; a dead
preparation with no published state is safely reconciled without deleting live or
published leases. Broker, binding, client, and native task share one bounded
1800-second attempt deadline.

Offline tests prove the registry/broker protocol with a fake socket client.
The exact pinned Phase 2 execution additionally live-proved
`subagentOnlyExtensions` loading and terminating submission through the native
`subagent(...)` tool. This proof is scoped to the recorded agent, extension,
Pi/subagent versions, and execution hashes; it is not a global propagation claim.
The resolver-census hardening added after that run is covered by offline tests and
is not retroactively attributed to the pinned live execution.

The six-review live pilot produced 6/6 strict broker-finalized artifacts and 6/6
independent immutable-Git recoveries. Two initial submissions were accepted;
five correction submissions completed inside the same model processes, with no
separate formatting/correction model reruns. A/B agreed on two PRs and disagreed
on Prefect. The one permitted Luna-xhigh fallback inspected source and produced
one 3,394-byte assistant JSON text, but `structured_output` was absent and the
text failed the requested simplified schema (missing `decision`, wrong
`unknowns` shape, and additional fields). The detached text was not an accepted
typed artifact and is not truth. No second fallback was launched, so Prefect
remains `unknown`. Full non-private results are frozen in
`native-pilot-report-v1.json`; no artifact was imported into the canonical DB.

The native parent reported 0/3 success in each wave even though all six eventual
escrows validated, because historical tool errors or terminating no-output
dominated its task status. Broker escrow remains authoritative. Medium typed
submission is `GO`; scale remains `NO_GO` until native status semantics and an
xhigh typed terminal surface are fixed. Per-attempt report costs preserve the
provider-observed USD totals; deterministic session audits additionally publish
integer micro-USD values rounded once per session, so summed audit micro-USD can
differ slightly from rounding the exact aggregate once.

## Runner CLI

```bash
python -m benchmarks.real_world.pilot_typed_run_v3 prepare-packets \
  --cache-root "$PRIVATE/cache" --v2-packet-root "$PRIVATE/packets" \
  --v3-packet-root "$PRIVATE/packets-v3"
python -m benchmarks.real_world.pilot_typed_run_v3 prepare-native-attempt \
  --cache-root "$PRIVATE/cache" --packet-root "$PRIVATE/packets-v3" \
  --execution-root "$PRIVATE/execution-typed-v3" \
  --repository OWNER/REPO --pr NUMBER --lane A --attempt-id ATTEMPT
python -m benchmarks.real_world.pilot_typed_run_v3 create-native-agent \
  --execution-root "$PRIVATE/execution-typed-v3" \
  --output "$HOME/.pi/agent/agents/benchmark-pilot-v3-private/pilot-blind-reviewer-luna-medium-v3.md"
python -m benchmarks.real_world.pilot_typed_run_v3 native-launch-plan \
  --execution-root "$PRIVATE/execution-typed-v3" --attempt-id ATTEMPT
# Parent now passes only result.subagent_call to the native subagent tool and
# retains result.authentication with the execution record.
python -m benchmarks.real_world.pilot_typed_run_v3 finalize-native-attempt \
  --execution-root "$PRIVATE/execution-typed-v3" --attempt-id ATTEMPT
python -m benchmarks.real_world.pilot_typed_run_v3 audit-native-sessions \
  --execution-root "$PRIVATE/execution-typed-v3" \
  --session ATTEMPT=/absolute/pinned/session.jsonl
```

The session audit accepts an eventual validated escrow even when a historical
tool error makes the native parent status look failed. It reauthenticates the
binding, exact escrow, receipt, and immutable Git evidence; requires model and
thinking bindings before assistant activity; and requires the successful submit
tool result to be terminal. It also fails closed on tools or paths outside
policy, prose, malformed JSONL, tool/result cardinality, non-integer token
counters, non-finite/negative cost, and submission bounds.

`create-native-agent` copies the exact hash-bound execution agent to a mode-0400
agent definition below the recognized Pi user discovery root and atomically
freezes its real path, bytes, exact pinned-resolver output, discovery-root census,
and census hash in an installation receipt. `native-launch-plan` independently
rebuilds that census and refuses missing, stale, shadowed, duplicate, symlinked,
or modified installations. Resolver tests cover `~/.agents`, changed
`PI_CODING_AGENT_DIR`, and a same-name agent delivered by a settings-configured
package. `PI_SUBAGENT_EXTRA_AGENT_DIRS` is rejected because this profile does not
silently omit additional resolver roots. Tests may isolate discovery with
`--user-agent-root` / `--builtin-agent-root` (or the corresponding
`PILOT_PI_USER_AGENT_ROOT` / `PILOT_PI_BUILTIN_AGENT_ROOT` variables); production
uses Pi's user and installed-package locations. Execution and packet parents must
already be private mode-0700 directories.

## Validation commands

```bash
.venv/bin/python scripts/run_tests_bounded.py \
  tests/benchmarks/test_pilot_submit_v3.py --pytest-arg=-x --timeout-seconds=300
.venv/bin/ruff check benchmarks/real_world/pilot_submit_v3.py \
  tests/benchmarks/test_pilot_submit_v3.py
MYPYPATH=src .venv/bin/mypy --strict --explicit-package-bases \
  benchmarks/real_world/pilot_submit_v3.py benchmarks/real_world/pilot_typed_run_v3.py \
  tests/benchmarks/test_pilot_submit_v3.py tests/benchmarks/test_pilot_typed_run_v3.py
# Tests use a socket-protocol-equivalent fake child and never invoke a real model.
# The separately recorded pinned live execution supplies the scoped live proof.
```
