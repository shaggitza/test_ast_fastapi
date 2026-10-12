# GH104 controlled-synthetic phase assay

This test-only harness can prepare a bounded runtime command for one newly
created, minimal FastAPI fixture. The application contains only `startup` and
`shutdown` no-op callbacks registered with `on_event`. It imports no service
code and contacts no URL.

## Fixture and static manifest

`write_fixture` requires a nonexistent destination directory, creates it
exclusively, and writes only `main.py`. Preparation checks that the root is a
nonsymlink directory containing exactly that regular file and that its bytes
match the embedded fixture SHA-256. A symlink, preexisting destination, added
file, or changed source fails closed.

The manifest is not assembled by hand. `static_phase_manifest` runs the
repository's `CustomSurfaceExtractor`, typed mypy provider, and
`collect_framework_phase_evidence`, then passes the integration report through
`manifest_from_report`. It rejects absent, unavailable, incomplete, or
unexpected callback records. It retains the source, inventory, engine, and
config digests from that report. The report and exact manifest are recomputed
immediately before command creation and execution.

`prepare_command` creates its own fixture in a new temporary root, makes the
source read-only and the root traversable, and returns the rendered
`VMExecutor` command for inspection. It does not start a container. The command
is inspection-only and cannot be launched: both the fixture root and temporary
cidfile directory are removed before the function returns. The explicit
`execute_raw_controlled_fixture` path separately creates a fresh root, renders
and executes its command before cleanup. It takes only an executor and cannot
be pointed at a caller application.

After static manifest validation and before command construction, the
execution root is mode `0555` and `main.py` is mode `0444`. This permits the
configured non-root worker UID to traverse and read the bind mount without
allowing fixture mutation. Cleanup restores the private root to `0700`, unlinks
only its exact `main.py`, and removes that root, including after failed static
analysis or execution.

## Result meaning and safety

The explicit execution path calls the bounded private command and execution
primitives to retain the raw phase observation, bypassing the public
`analyze_in_vm` self-report downgrade only for this owned fixture assay. A
positive result requires a raw worker payload with integer schema version 3,
worker status `ok`, worker phase `list`, completed lifecycle status, the
positive raw observation role, exact manifest agreement, and observations for
both expected callbacks. Empty,
partial, failed, or mismatched observations fail closed. Its result role is
`controlled_synthetic`; it is not `TrustedRuntimeEvidence`, a trust receipt, or
production positive evidence. Public VM sanitization, producer safeguards, and
comparison safeguards remain unchanged.

The request boundary also requires integer schema version 3 and phase `list`,
checks the complete projected manifest and its canonical digest, and reads a
request-file sidecar with an 8 MiB bound. Tests exercise the real
`VMExecutor._container_command` and mock only `_execute_bounded`; the large
request-file case wraps the real request builder only to cross its 64 KiB
transport threshold. They assert that source identities project to
`/workspace/app/main.py`, other identity and manifest fields are preserved,
and host and projected manifest digests differ. Malformed schema, phase,
projection, digest, status, and worker response cases fail before a positive
result is returned.

The command uses the checked-in executor's `runsc`, network isolation, private
IPC/PID namespaces, non-root identity, read-only root and fixture mount,
bounded temporary/output storage, CPU/memory/PID/ulimit caps, seccomp profile,
immutable image digest, and dependency-lock, snapshot-lock, SBOM, and policy
hash inputs. The preparation tests mock execution; the measured owner-run assay
below separately launched only the embedded fixture.

## Measured source-aligned assay

The result capsule is under
`benchmarks/results/framework-phase-controlled-v1/main68b-20261012/`.
`observed-result.json` and `worker-response.json` preserve the actual response
and comparison: both startup and shutdown were `observed_positive`, with
completed lifecycle execution and no unavailable rows. The owner-run command
exited 0 in 50.290 seconds, including host static analysis and guest execution.
The fixture SHA-256 is
`4ad05b1104ae5bd641ca27b3a9c3cb797e02d7f7fc4c5c533dd25413bce12062`.

The host analyzer was `7e1d95fcd3e40bd01bd508ab17163a2bbe32739b`, on
Python 3.11.16 and Mypy 1.19.1. The local image contains exact product source
from `68b174f17952eaadcd089be426438683d5bba6e3` and uses Python 3.11.17.
Its immutable reference is
`test-ast-runtime-phase-main68b-cont87@sha256:6cd983b64b21c18cb2a72afcc9b68cdaf9acdcd9bf35813f42641562f89ff4b0`.
Independent review reconciled all 81 installed package files and the source
pyproject with the 82-row source manifest. The ten dependency base layers were
unchanged. The derived SBOM explicitly references the prior dependency inventory
and the new source overlay; it is not a registry or runtime attestation.
The capsule includes the Dockerfile, locked requirements, source manifest,
derived SBOM, verification receipt, fixture lock, and byte checksums.

The policy SHA-256 was
`96280826c3dc7b732f07cb9018ac833dff90eea350fa54c3ebef0e8488c15bbd`;
the fixture-lock SHA-256 was
`8ec12184c36bc4037efc1dcef6219b80ff143833ecadabd5407e5f9cecb58c20`.
The installed `runsc` was release-20261005.0, binary SHA-256
`210b437a9cfae51e8f8c9074ed19b8b5e59477178e2e391a18117d8d6b924f7a`.
The result remains `controlled_synthetic`, with no production trust receipt,
canonical truth labels, or real-world precision/recall claim.

Two earlier owner attempts using the historical 15508bc image were rejected
before callbacks because that image's framework-v1 contract digest differed
from the host manifest. They were failures. The source-aligned image fixed
that compatibility mismatch while preserving the manifest validation.

## Prerequisites before a real assay

The executor configuration must be populated with reviewed, exact pins. Do not
reuse the historical pins below as evidence for this new fixture root or for
an image's contents. Before executing a prepared command, independently verify:

1. The immutable image digest and its embedded `runtime_worker.py` contents.
2. The exact dependency lock, snapshot lock, SBOM, seccomp profile, and expected
   policy digest for the reviewed image.
3. The installed `runsc` binary and Docker runtime registration.
4. The fully rendered command and its fixture mount, manifest, and resource
   bounds.

Historical records for image
`test-ast-runtime-phase-15508bc@sha256:8c2d95773208aab2a4391316ba4bd6446ac6d896ba581420545053822d9f24e4`
reported worker UID/GID `65532:65532`, dependency-lock hash
`sha256:a9b9ba4e4dd4507e4ddd1e64bfbaa3c4680caddcb056aa81fc396e007f02d3d5`,
snapshot-lock hash
`sha256:f001875849647490389662178ef6b58a7083d0ff342b539c7ca38f7432f8d243`,
SBOM hash
`sha256:150519b5360cc6e47acf198191e514bcc879fb4b6c71272b075cec4181d61961`,
and seccomp hash
`sha256:96dbac26aac6041de88eaf99f653d606933469dd104157b877190d998ab68d4a`.
These are historical values only. Matching a checked-out worker source hash
does not establish the contents embedded in an image. The public runtime
protocol identity also does not establish compatibility with a new image.
