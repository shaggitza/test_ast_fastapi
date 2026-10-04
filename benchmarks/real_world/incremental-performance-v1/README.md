# Incremental performance measurement protocol v1

Run `uv run --frozen python -m benchmarks.real_world.measure_incremental
--repeats 5 --output /tmp/gh283-performance.json`, or use the explicit runner
shortcut `uv run --frozen python benchmarks/real_world/run_current.py
--performance-mode --performance-repeats 5 --performance-output
/tmp/gh283-performance.json`. The shortcut uses only generated source in a
temporary directory and does not open or execute the frozen third-party corpus.

The fixture has 96 typed modules in a deterministic DAG, a typed endpoint, and
an unrelated dead-code control. Each source file has a SHA-256 inventory. The
protocol verifies that the endpoint reaches the expected DAG and not the dead
control; changes exactly one typed source file between target snapshots. It
records baseline/target preparation, cold analysis build, cache-fingerprint
verified warm no-change query, changed-snapshot execution, process peak RSS,
and endpoint-cache byte size separately. Timings report
raw samples and nearest-rank p50/p95/max; no performance threshold is inferred
from an unsupported phase.

## Backend capability and claims

The current `MypyAnalyzer` invokes mypy with `Options.incremental = False`.
Its JSON cache persists endpoint dependency results, not mypy build state. A
fresh analyzer can return a warm no-change result only after the source/tool
fingerprint validates. A one-file change mismatches that fingerprint and runs
a full analyzer build. The report therefore marks `one_file_incremental_update`
as `unsupported` and records the elapsed changed-snapshot full rebuild in its
own phase. That rebuild time must never be presented as incremental latency.
This protocol cannot satisfy the GH283 incremental p95 <=30s gate until the
backend supports and proves incremental invalidation/reuse. Peak RSS and cache
bytes are separate quantities and do not constitute an incremental claim.

Reports include Python/platform, mypy version, analyzer source/config/cache
fingerprints, fixture inventory hash, changed file, and per-attempt phase
samples. These are synthetic trusted-source measurements, not frozen corpus
results and not a user-project performance guarantee.

## Recorded run

The checked-in [`measurement.json`](measurement.json) contains five actual
Python 3.11.16 / mypy 1.19.1 samples over 98 inventoried Python source files
(96 DAG modules, one route module, one dead control). Measured p50 / p95 / max:

| Phase | p50 | p95 | max |
| --- | ---: | ---: | ---: |
| Baseline/target preparation | 0.0793 s | 0.2213 s | 0.2213 s |
| Cold analysis build | 5.3561 s | 6.6145 s | 6.6145 s |
| Verified warm no-change query | 0.0513 s | 0.0933 s | 0.0933 s |
| Changed-snapshot full rebuild | 4.3883 s | 6.3429 s | 6.3429 s |

The five cache files were 11,427 bytes each. Whole-process peak RSS was
535,314,432 bytes (one process high-water observation). The changed-snapshot
phase is a full rebuild, so there is no measured incremental-update latency or
incremental p95 to compare with the 30-second requirement.
