# Isolated runtime comparator

Runtime import is an optional comparator for trusted/frozen experiments. It is
not ground truth and never replaces the execution-free secure-AST artifacts.
The host process must never import third-party application code.

## Required boundary

`--vm` now fails closed unless Docker resolves the configured image to exactly
one immutable repository digest and a non-default isolation runtime is
available. The default runtime name is gVisor's `runsc`; `runc` is rejected.
Set the immutable image explicitly:

```bash
export FASTAPI_ENDPOINT_DETECTOR_VM_IMAGE='registry.example/detector@sha256:<64-hex>'
export FASTAPI_ENDPOINT_DETECTOR_VM_LOCK_SHA256='sha256:<64-hex>'
export FASTAPI_ENDPOINT_DETECTOR_VM_SNAPSHOT_SHA256='sha256:<64-hex>'
export FASTAPI_ENDPOINT_DETECTOR_VM_SBOM_SHA256='sha256:<64-hex>'
fastapi-endpoint-detector list --vm --app ./application
```

The image must already contain all snapshot-pinned dependencies, declare no
`Config.Volumes`, and is never pulled during a comparator launch. The CLI no
longer builds a mutable image automatically. Content-addressed dependency-lock,
source-snapshot-lock, and SBOM attestations are mandatory launch inputs. Their
production remains a
release-pipeline responsibility; benchmark manifests record all three hashes,
the image digest, and `VMExecutor.policy_provenance()`. The packaged seccomp
profile has a pinned digest in the executor; a custom profile requires
`FASTAPI_ENDPOINT_DETECTOR_VM_SECCOMP_SHA256` and must match it exactly.

## Policy v1

Docker Engine and CLI 29.0 or newer (API 1.52+) are the documented minimum.
Bind mounts use Docker 29's `bind-recursive=disabled`; the removed
`bind-nonrecursive` spelling is intentionally not emitted.

Every launch uses argv without a shell and enforces:

- an explicit allowlist of gVisor/Kata runtime names rather than arbitrary or
  default OCI runtimes;
- no daemon image pull, network, IPC sharing, retained container logs, devices,
  host sockets, privileges, or added capabilities;
- non-root UID/GID `65532:65532` and `no-new-privileges`;
- a read-only root and exact, read-only, non-recursive app/diff mounts; mount
  grammar metacharacters, symlinked or unreadable trees, special files,
  filesystem-root, home-root, and other broad system mounts fail before Docker
  starts;
- a 64 MiB `noexec,nosuid,nodev` tmpfs;
- memory=swap, CPU, PID, `nofile`, `nproc`, `fsize`, core, timeout, and combined
  stdout/stderr limits;
- a clean explicit process environment;
- the versioned deny-by-default seccomp profile at
  `executor/policies/runtime-seccomp-v1.json`;
- a unique container name plus CID file, followed by kill, forced removal, and
  successful bounded inventory queries proving both identifiers absent on
  success, failure, timeout, or output overflow.

The policy and seccomp bytes are content-addressed in provenance. Missing
Docker, runtime, digest, profile, app, diff, malformed JSON, or endpoint schema
produces an explicit error; there is no fallback to host import.

## Remaining comparison work

Issue #100 owns paired secure/runtime measurements and disagreement
adjudication. Equivalent app/factory/bootstrap selection, snapshot dependency
images, SBOM attestation, structured import/app/extraction phases, and runtime
RSS collection must be frozen before corpus numbers are interpreted. Runtime
absence proves little; runtime-only routes identify static discovery gaps but do
not automatically become canonical truth.
