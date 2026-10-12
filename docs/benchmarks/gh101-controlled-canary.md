# GH101 controlled sandbox canary assay

This harness prepares and explicitly runs an owned local canary assay. It executes only a script generated from the constant in `tests/benchmarks/controlled_sandbox_canary.py`; it never imports an archived project, upstream application, SDK, or client. Its result label is always `controlled_synthetic` and is not trusted runtime evidence.

## Safety boundary

The helper defaults to inspection only. It constructs the VMExecutor command, prints its shell rendering and pin metadata, then deletes its private temporary fixture. It does not launch Docker in this mode. `--execute` is an explicit opt-in for the later owner-launched run. That mode has two independent temporary fixture roots: a canary and a host-deadline assay. Each contains exactly one generated source file, checked against its hash before mount, owned by the helper, and mounted read-only. The synthetic marker is a separate mode-0600 file outside the mount. Cleanup removes only the helper's own temporary roots.

The canary checks that the marker is invisible, a write to the mounted source fails, and a connection attempt to the reserved TEST-NET address fails. If networking unexpectedly succeeds, the canary fails. It sends no request to a real external host. The second owned command is intended to loop, but a host-side VMExecutor deadline can expire while Docker or gVisor is still starting. Therefore `host_execution_deadline_observed` records only the exact configured host execution deadline; it does not prove the guest loop started or ran. A test-only `RecordedExecutor` captures the generated name, exact command hash, and a strictly validated 64-hex CID using a read capped at 129 bytes; only regular files with at most 128 bytes are accepted. It writes that validated value to a private snapshot and passes the snapshot to VMExecutor's unchanged cleanup method, binding the kill/remove target and CID absence query to the captured value even if the original CID file changes. Missing, invalid, oversized, or unreadable input is represented by an empty private snapshot so core cleanup still targets and verifies the generated name. `cleanup_verified` is true only when a CID was captured and core kill/remove plus exact name and CID absence checks succeeded. Cleanup/query failures remain incomplete, even when the host deadline itself was observed. No guest-ready state is inferred.

The command uses the existing VMExecutor policy: pinned image, `runsc`, `--network none`, UID/GID 65532, read-only root and bind, dropped capabilities, no-new-privileges, the pinned deny-by-default seccomp profile, bounded noexec tmpfs, resource limits, clean environment, and bounded output. The helper does not weaken or replace these controls. It never inspects or removes unrelated containers.

## Pins

The supplied image reference is `test-ast-runtime-phase-15508bc@sha256:8c2d95773208aab2a4391316ba4bd6446ac6d896ba581420545053822d9f24e4`. Read-only `docker image inspect` metadata returned user `65532:65532`, no declared volumes, and the matching repository digest. Inspection mode starts no container; the measured run below separately started only the two generated fixtures.

The dependency lock is SHA-256 `a9b9ba4e4dd4507e4ddd1e64bfbaa3c4680caddcb056aa81fc396e007f02d3d5` from `/tmp/test-ast-runtime-image-build-20261010/requirements.lock`. The SBOM is SHA-256 `150519b5360cc6e47acf198191e514bcc879fb4b6c71272b075cec4181d61961` from `/tmp/test-ast-runtime-phase-15508bc-validation-20261010/machine-sbom.json`. The packaged seccomp profile is SHA-256 `96dbac26aac6041de88eaf99f653d606933469dd104157b877190d998ab68d4a`. For this generated canary source, the source hash is `42ea8eac3e7b7e8aceddcb8d4536a4cb76deb0f3bbc41200a6ef2f225801025d`; its fresh single-file fixture-lock hash is `bd0d1b6c48ab3a0df9200058af7f36be059880136f53acef975315a63288bdde`. Inspection output recorded VMExecutor policy hash `c3fb05181d2cbb8d8619f772e4198b62ed4b2bc226d334ce2c3d1bc92519cd48` and command hash `63ba2316d586bd159709f99247d45f688da4673a2a3e74f606c312d0949c4847`. At run time, output records the actual generated source hash, a fresh single-file fixture-lock hash, these dependency/SBOM/seccomp pins, VMExecutor's policy hash, image, exact argv, and argv hash as distinct identities. The recorded identity hashes are all distinct.

## Commands

Inspection-only preparation (safe default):

```sh
PYTHONPATH=src /tmp/pr341-ci-host-locked-20261010/bin/python -B tests/benchmarks/controlled_sandbox_canary.py
```

Owner-launched canary and timeout assay, only after parent review:

```sh
PYTHONPATH=src /tmp/pr341-ci-host-locked-20261010/bin/python -B tests/benchmarks/controlled_sandbox_canary.py --execute --temp-parent /tmp
```

The executable command requires the pinned image to exist locally, compatible Docker daemon/API and installed gVisor `runsc` at `/opt/test-ast-gvisor-20261005.0/runsc`, and the source lock/SBOM paths above. It uses `--pull never`; it will fail closed if pins, seccomp, image, runtime, or cleanup verification are unavailable. The timeout assay cannot establish guest-loop execution without a positive guest-ready signal. Do not treat mocked tests or inspection output as an operational pass.

Focused offline tests (guest execution mocked; includes bounded CID capture, changed-source-path binding, capture failures, and cleanup-failure receipts):

```sh
PYTHONPATH=src /tmp/pr341-ci-host-locked-20261010/bin/python -B -m pytest -q -oaddopts='' tests/benchmarks/test_controlled_sandbox_canary.py
```

The helper and its offline validation are:

- `tests/benchmarks/controlled_sandbox_canary.py`
- `tests/benchmarks/test_controlled_sandbox_canary.py`
- `docs/benchmarks/gh101-controlled-canary.md`

## Measured owner-run CID assay

The capsule at `benchmarks/results/controlled-sandbox-canary-v1/cid-cont89-20261012/` preserves the actual result and independent post-run container inspection. On helper revision `7bfd65b233d1ef54c302f408d1bfefd26af578ba`, host Python 3.11.16 and Mypy 1.19.1, the command exited 0. All three canary checks passed: the out-of-mount inert marker was hidden, the read-only source write failed, and the TEST-NET connection was unavailable.

Both generated commands captured their actual 64-hex CIDs before cleanup. The unchanged core cleanup targeted those snapshot CIDs and verified absence by CID and generated name. Four additional parent `docker container inspect` calls independently returned `No such container` for the two CIDs and two names. The timeout record establishes the configured host deadline and completed CID cleanup; guest-loop start remains unknown. No upstream application, SDK, service, or client was run. These are controlled synthetic observations, with no production trust receipt.

The result SHA-256 is `63a60b12214f30718d47eb9ff62d1c2e1cbc4f441b463b56de26beba0e14182f`. The capsule's checksums bind the original result and cleanup-check bytes.
