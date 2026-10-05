# Pyright differential evaluation v3

This bounded pilot runs the official Pyright CLI `1.1.411` and mypy `2.4.0`
against six synthetic fixtures only. It records diagnostics and typed output
observations. It does not run corpus applications, establish execution or
reachability, provide definition-target queries, or establish canonical truth.
Cross-engine diagnostic semantics remain unsupported; the only comparison is
overlap of comparable error locations. Missing diagnostics are not evidence of
equivalence.

## Reproduce

Requirements: POSIX/Linux, Node.js and `uv`. Process-group cleanup is part of
the bound; this runner does not claim Windows process-tree containment. Install
the exact provider versions into
dedicated locations (do not resolve a generic `mypy` from an ambient `PATH`):

```sh
npm install --prefix /tmp/pyright-differential pyright@1.1.411
uv tool install --force mypy==2.4.0
export PYRIGHT_DIFFERENTIAL_PYRIGHT=/tmp/pyright-differential/node_modules/.bin/pyright
export PYRIGHT_DIFFERENTIAL_MYPY="$(uv tool dir)/tools/mypy/bin/mypy"
```

Run one fixture, or reproduce all v3 records in the required order:

```sh
RESULTS_DIR="$(mktemp -d)/pyright-differential-v3"
for fixture in callable overloads package_layout receiver shadowing utf8; do
  uv run python -m benchmarks.providers.pyright_differential "$fixture" \
    --pyright "$PYRIGHT_DIFFERENTIAL_PYRIGHT" --mypy "$PYRIGHT_DIFFERENTIAL_MYPY" \
    --results-dir "$RESULTS_DIR"
done
uv run python -m benchmarks.providers.pyright_differential --verify-records \
  --results-dir "$RESULTS_DIR"
uv run --with pytest python -m pytest -q tests/benchmarks/test_pyright_differential.py
```

Set both environment variables when running pytest to enable its real-tool
integration case. It checks exact CLI versions before invoking them. The run
records resolved executable and package metadata SHA-256 values, normalized
package-relative command identities, fixture/config hashes, consumed snapshot
hashes, engine versions, and the actual limits. Command paths in records are
stable package aliases; local install paths do not become claimed provenance.
The npm package metadata and mypy distribution metadata identify the pinned
official packages. These hashes are reproducibility evidence, not signed
attestations.

## Bounds and recommendation

Each provider invocation has a 25-second wall-clock deadline, a combined
2,000,000-byte stdout/stderr cap, and a dedicated process group. Timeout or
output overflow kills that process group, including ordinary descendants that
remain in it. A provider that deliberately creates a new session can escape
this process-group cleanup; this pilot is resource-bounded for controlled
official CLIs, not a hostile-code sandbox. Each fixture is limited to 32 files
and 256,000 input bytes; symlinks, non-source files, and inherited Pyright
configuration are rejected. Inputs are snapshotted and checked before and
after each invocation. Reproduction writes only to the new immutable v3 result
directory; historical v1/v2 records remain unchanged.

**Recommendation: HYBRID for this timeboxed capability only.** Retain the
controlled Pyright/mypy run as a bounded typed-observation source alongside
other evidence, while treating location overlap as a narrow diagnostic
comparison. This pilot does not pass or claim the full GH284 roadmap, corpus
gates, endpoint/reachability analysis, definition mapping, or canonical-truth
requirements.
