# Runtime sandbox policy v1

Issue: [#101](https://github.com/shaggitza/test_ast_fastapi/issues/101)

This release hardens the runtime-import comparator before any third-party corpus
execution. It deliberately publishes no secure-vs-runtime quality numbers.

## Merge gates

The command builder and lifecycle tests attest:

- immutable repository-digest resolution with ambiguity rejection;
- mandatory dependency-lock, source-snapshot-lock, SBOM, and seccomp SHA-256
  attestations;
- an explicit gVisor/Kata runtime allowlist (`runc` and unknown runtime names are
  rejected);
- no image pull, network, host environment inheritance, IPC sharing, retained
  logs, devices, privileges, capabilities, sockets, or writable checkout/root;
- non-root execution, read-only non-recursive mounts, deny-by-default seccomp,
  and bounded noexec tmpfs;
- memory/swap, CPU, PID, nofile, nproc, fsize, core, timeout, and output limits;
- unique name/CID cleanup with post-removal inspection;
- deterministic content-addressed policy provenance and rejection of mutated
  policy bytes, broad/symlinked mounts, special files, and malformed CID values;
- malformed output and endpoint schema rejection.

The wheel build contains
`fastapi_endpoint_detector/executor/policies/runtime-seccomp-v1.json`.
Runtime execution remains opt-in and requires a prebuilt image. There is no host
import and no automatic mutable image build.

## Deferred operational gate

Corpus runtime imports remain blocked until snapshot-specific images are built
with pinned locks and SBOMs, the configured host exposes gVisor/Kata, and a
trusted canary verifies the seccomp allowlist under both `list` and `analyze`.
Issue #100 owns the paired protocol, structured phase failures, route/impact
comparisons, and source adjudication. Runtime remains a comparator, not truth.
