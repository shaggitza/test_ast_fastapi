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

The required phase-2 gate is a disposable exact-version `pi-subagents` launch
using an agent with:

```yaml
tools: read, grep, find, ls, submit_blind_review
extensions:
subagentOnlyExtensions: /absolute/hash-bound/repository/.pi/extensions/blind-review-submit/index.ts
```

That gate must prove child-only tool availability, successful terminating submit,
no artifact prose, exact escrow, transcript/resource capture, parent
revalidation, and cleanup. The absolute extension path and bytes must be frozen
in each execution manifest because the child cwd is the private packet.

Luna-medium plus the optional Luna-xhigh semantic fallback is tracked separately
by issue #218. No xhigh trigger/orchestration is implemented or claimed here.

## Validation commands

```bash
.venv/bin/python scripts/run_tests_bounded.py \
  tests/benchmarks/test_pilot_submit_v3.py --pytest-arg=-x --timeout-seconds=300
.venv/bin/ruff check benchmarks/real_world/pilot_submit_v3.py \
  tests/benchmarks/test_pilot_submit_v3.py
MYPYPATH=src .venv/bin/mypy --strict --explicit-package-bases \
  benchmarks/real_world/pilot_submit_v3.py tests/benchmarks/test_pilot_submit_v3.py
# Exact extension loading and child propagation are phase-2 live gates; the
# phase-1 test suite intentionally makes no claim from an offline CLI exit code.
```
