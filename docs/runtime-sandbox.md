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
export FASTAPI_ENDPOINT_DETECTOR_VM_SBOM_SHA256='sha256:<64-hex>'
fastapi-endpoint-detector list --vm --app ./application
```

The image must already contain all snapshot-pinned dependencies. The CLI no
longer builds a mutable image automatically. A content-addressed dependency lock
and SBOM attestation are mandatory launch inputs. Their production remains a
release-pipeline responsibility; benchmark manifests record both hashes, the
image digest, and `VMExecutor.policy_provenance()`.

## Policy v1

Every launch uses argv without a shell and enforces:

- gVisor/Kata runtime rather than the default OCI runtime;
- no network, devices, host sockets, privileges, or added capabilities;
- non-root UID/GID `65532:65532` and `no-new-privileges`;
- a read-only root and exact, read-only, non-recursive app/diff mounts;
- a 64 MiB `noexec,nosuid,nodev` tmpfs;
- memory=swap, CPU, PID, `nofile`, `nproc`, `fsize`, core, timeout, and combined
  stdout/stderr limits;
- a clean explicit process environment;
- the versioned deny-by-default seccomp profile at
  `executor/policies/runtime-seccomp-v1.json`;
- a unique container name plus CID file, followed by kill and forced removal on
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
