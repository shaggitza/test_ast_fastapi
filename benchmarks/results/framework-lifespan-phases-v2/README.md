# Framework lifespan phases v2

This phase adds execution-free, phase-sensitive FastAPI lifespan surfaces.

## Frozen controlled behavior

For an exact `FastAPI(lifespan=lifespan)` registration where `lifespan` is a
project-local async generator with one unconditional top-level `yield`:

- pre-yield statements and their typed descendants reach only
  `FRAMEWORK.LIFECYCLE lifespan:startup`;
- post-yield statements and their typed descendants reach only
  `FRAMEWORK.LIFECYCLE lifespan:shutdown`;
- the yield boundary is preserved in handler-range evidence;
- conditional, nested, missing, and multiple yields produce no phase surface and
  retain an inventory limitation.

The implementation never imports application code and does not recurse through
FastAPI or contextlib internals. It uses strict schema-v3 constructor contracts,
exact callback identity, immutable contract/source hashes, and snapshot-local
mypy traversal.

## Validation

The controlled integration fixture changes a transitive startup descendant and
asserts that shutdown is absent. Existing decorator lifecycle, middleware,
background-task, surface-schema, and extraction tests remain unchanged. Full
validation uses the resource-bounded per-file runner.

## Deferred

Starlette constructor lifespans, callback aliases/factories, exception-path
feasibility, startup-added route mutation, and class middleware remain open
under Issue #104.

The isolated worker now accepts a versioned `framework-phase-manifest-v1` with
the `lifespan` worker phase. It checks callback and registration source-file
digests inside the container, loads the selected app in a disposable child of
the container worker, matches the loaded lifespan callable by file, function
name, and definition line, and drives the app's ASGI lifespan startup/shutdown
messages. It records a callback phase only if Python tracing sees that exact
callback code frame execute during that phase; ASGI completion alone does not
attribute execution to a callback. It rejects invalid or out-of-order ASGI
completion messages. Its `framework-phase-observation-v1` payload contains
positive observations only; mismatch, skipped callback, startup failure, or
source drift is reported as unavailable. The VM executor passes this request
through the same pinned image, read-only mount, gVisor, network-disabled,
seccomp, and resource-limited path as list/impact requests.

The benchmark producer now verifies an operator-signed host receipt against an
out-of-band `FASTAPI_DETECTOR_RUNTIME_TRUST_KEY` and key ID. The authenticated
receipt is bound to the exact source snapshot, invocation, image, dependency,
SBOM, seccomp, and runtime policy pins, and has a bounded freshness window.
Without both trust settings, it fails closed before calling a runtime runner.
Controlled signing tests exercise this protocol only; they are not host
attestation or isolated runtime evidence. The current trust setting is an
operator provisioned HMAC key, so it must remain secret from receipt producers
and must not be sourced from the receipt itself.

The producer now obtains the manifest from the secure AST impact report, maps
its staged source identities back to the pinned snapshot, and passes it to both
runtime list/impact worker invocations. Each invocation must return a validated
phase observation. The host broker retains that observation and manifest in its
per-invocation custody result; the comparator verifies both signatures,
manifest identity, observation digest, snapshot source identity digests, and
observation/result equality. Missing phase observations make a successful
runtime record invalid. Phase output remains a separate positive-observation
comparison and cannot promote runtime inventory to canonical truth or treat an
unobserved callback as proof of absence.

The runtime manifest accepts fully bound FastAPI
lifespan callbacks and startup/shutdown event handlers when the loaded callback
is present in the selected app router's matching registration table. This is
registration-table and executed-code evidence for the selected process only;
it does not attest producer source, inventory, engine, or configuration pins.
The worker validates file digests from its request but does not independently
attest inventory, source snapshot, engine, or configuration hashes. The host
binds the result to operator-pinned producer inputs and checks the worker's
container manifest digest before translating identities back to the mounted
host snapshot. Controlled signatures and fake VM responses exercise protocol
behavior only. No producer-generated isolated application artifact is published
for this revision, so no operational application runtime positive is claimed.

Startup failure, source or manifest tampering, callback identity mismatch,
unavailable lifecycle callbacks, custody tampering, missing observations,
wrong snapshot side, replayed challenges, and unsigned runtime results remain
failures or unavailable states. An unavailable callback is not an absence
claim.


## Controlled isolated-image verification at 15508bc

The retained Mypy graph repair was independently reviewed at exact source
`15508bc8a477fb6fad170df0be0b95e0b2e3fc79`: the combined 76 phase/producer tests,
strict source type checks and Ruff checks passed. It reuses a source-verified
retained typed graph, with bounded file reads and directory traversal that
rejects symlinks, rather than rebuilding the frontend for the phase report.

[Controlled artifacts](controlled-15508bc/artifact-sha256.json) retain two
synthetic baseline/target comparisons using the same fixture and the exact
image `test-ast-runtime-phase-15508bc@sha256:8c2d95773208aab2a4391316ba4bd6446ac6d896ba581420545053822d9f24e4`.
The default selection and an explicit `main:app` selection each produced two
successful secure records and two runtime abstentions: `unavailable`, with
`static runtime phase coverage is conditional`. Both comparisons have zero
eligible successful runtime pairs and no runtime quality metrics. The secure
inventory marks the HTTP route conditional because its startup/shutdown
registrations leave a route-state limitation. Neither selection clears that
limitation; no complete application runtime observation is claimed.

The image was built offline from the 76 committed source blobs and the same
pinned dependency image. All 31 source/provenance/sandbox checks passed,
including gVisor, UID/GID 65532, network disabled, read-only root, dropped
capabilities, no host binds, the pinned seccomp profile and verified cleanup.
The checks used the existing 512 MiB memory, 0.5 CPU, 128-process and 64 MiB
no-exec temporary filesystem policy. Application comparisons retained the
existing 60-second runtime timeout. Sanitized infrastructure summaries retain
the original receipt hash; private signing keys are excluded.

These are locally controlled synthetic operational records, not independent
host attestation, corpus truth, performance acceptance or a runtime speedup.
Application-process callback claims remain `self_reported_nonpositive`; the
host discards them as positive evidence even when broker custody is signed.
A trusted independent observer, complete phase coverage, peak RSS collection,
real-world evaluation and the original GH104 acceptance remain open.
