# GH97 Motor binding probe

`historical-source-only-v1.json` preserves the original unbound result byte for
byte from commit `c376830`: 21,649 bytes, SHA-256
`cabcfb198491c16788146f4983d650de5189238a99514e4d23194662fd0113e8`.
It records producer `dd615f5c3fd298f5aa854a8e2c42b26a5bd0f404` and the
original five calls with zero matches. Historical regressions use this fixed
snapshot. `result.json` contains the separately replayed production-binding
result from committed producer `c610ed795bc05cc5fe3ad9db13e4d50f8052dd19`;
its raw SHA-256 is
`fe43637e364c318129f3a0ec4deb9fd9c07ea42d6ca2f07e82fbe6147ab6543d`.
An independent replay reproduced these bytes exactly. Its own revision and
source hashes identify the producer it validates.

This probe asks whether the current exact-symbol MongoDB preset binds typed
Motor collection writes using Motor 3.6.0 and PyMongo 4.10.1 source. It does
not claim installed-package or runtime behavior. It never imports either
upstream package. It inspects only bounded `.py`, `.pyi`, `py.typed`, and
wheel `METADATA` members from the two supplied wheels, after hashing each wheel
byte snapshot once. It then passes a typed fixture to the repository's real
`MypyAnalyzer` and `audit_effect_contracts`.

Wheel bytes must match the two hardcoded SHA-256 digests before source
extraction. The runner checks its source, preset, and product module bytes against the
committed Git revision before and after replay. Each loaded product module
must resolve to this checkout's exact
source file. Reported product paths are relative to the checkout so the stored
result can be checked after cloning it elsewhere.

Run from this worktree with the root Python 3.11.16 environment:

```sh
cd /path/to/checked-out/repository
PYTHONPATH="$PWD/src" /path/to/python \
  benchmarks/gh97_motor_binding/run.py \
  --artifacts /tmp/gh97-wheel-audit \
  --output benchmarks/gh97_motor_binding/result.json
```

The output pins interpreter, mypy, artifact hashes, extracted source hashes,
the package versions read from extracted wheel metadata, the exact source bytes
whose digest matches mypy's parsed digest, analyzer source hashes, preset hashes,
typed source fixture hash, call resolution, and audit classification. The audit
requires both the expected Motor version and the exact pinned Motor declaration
hashes before matching a Motor contract; absent or mismatched evidence leaves
the call unmatched with `package_applicability_unverified`. The probe runs a
cold build and a fresh-analyzer warm cache replay, and requires identical audit
occurrences and applicability evidence. On a cache hit, the analyzer rebuilds
typed source state to revalidate declaration and metadata bytes rather than
restoring editable hash claims from the cache. Results are limited to the exact
artifacts named in the output. `unsupported_or_ambiguous` is a valid finding;
the runner does not invent canonical symbols to manufacture matches.

Cases include typed insert/update/delete calls, unrelated same-name receivers,
an imported type alias, an unsupported `Any` factory, missing and unexpected
arguments, and a wrapper method. The pinned run resolves and binds the three
valid Motor calls, leaves the two unrelated receivers unmatched, and leaves the
`Any` receiver unresolved. Mypy reports the invalid argument cases separately.
The effect auditor currently matches contracts by exact symbol and invocation;
its `matched` label does not certify argument validity. No API/network/service
calls are made. The probe uses temporary source extraction and deletes it on
exit.
