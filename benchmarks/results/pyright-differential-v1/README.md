# Pyright differential typed-oracle timebox

Run from the repository root (Node.js 22 and Python 3.10+):

```sh
npm install --prefix /tmp/pyright-differential pyright@1.1.411
uv tool install mypy==2.4.0
uv tool install ruff==0.16.10
PYRIGHT=/tmp/pyright-differential/node_modules/.bin/pyright
MYPY=$(command -v mypy)
RESULTS=/tmp/pyright-differential-results-v2
for fixture in package_layout callable receiver overloads shadowing utf8; do
  python3 benchmarks/providers/pyright_differential.py "$fixture" \
    --pyright "$PYRIGHT" --mypy "$MYPY" --results-dir "$RESULTS"
done
python3 benchmarks/providers/pyright_differential.py --verify-records --results-dir "$RESULTS"
```

The harness analyzes only the six synthetic fixture directories under
`benchmarks/providers/fixtures/pyright_differential`. Per invocation it limits
inputs to 32 Python files, 256 KB of source, and 25 seconds per provider. Each
record captures source and config SHA-256 hashes, reported engine versions,
commands, elapsed time, diagnostics and mypy `reveal_type` observations. The
original six v1 records remain preserved here. New runs write v2 records to
`benchmarks/results/pyright-differential-v2/`.

The v2 harness snapshots fixture bytes into a private temporary directory before
either provider starts, rejects symlinks and out-of-root paths, runs mypy with a
generated explicit Python 3.10 config, and checks that source and snapshot hashes
remain unchanged. Each record binds consumed source/config SHA-256 maps, provider
versions, commands, elapsed time, diagnostics, full Pyright ranges, and mypy
`reveal_type` observations. The verifier requires strict unique finite JSON, all
six fixtures exactly once in each record set, exact source/config coverage, and
internally consistent comparison and provenance fields. Mocks are used only in
tests and are not saved as provider results.

Pyright 1.1.411 is pinned from the official Microsoft npm package/release. Its
official CLI contract documents `--outputjson`, diagnostic ranges and JSON
shape; this CLI does not offer a definition query. Consequently definition
targets and execution/reachability are explicit unsupported observations.
Diagnostics are summarized only by overlapping error locations. Raw provider
rules and messages remain distinct; semantic diagnostic equivalence is
unsupported. A missing diagnostic is not evidence of equivalence. `reveal_type`
text is preserved as a typed observation and is not conflated with diagnostic
overlap or runtime behavior. See the [official CLI
documentation](https://github.com/microsoft/pyright/blob/main/docs/command-line.md),
[installation documentation](https://github.com/microsoft/pyright/blob/main/docs/installation.md),
and [official releases](https://github.com/microsoft/pyright/releases).

## Timebox decision

**HYBRID for this capability only:** retain mypy as the existing semantic
provider and permit Pyright as an optional, bounded differential typed oracle
for controlled fixtures. Do not use this result to decide the full GH284
architecture, promote execution edges, satisfy corpus gates, or claim that
either provider's silence validates an observation. This evaluation does not
implement definition/reference LSP queries, CFG, canonical source inventory,
runtime evidence, corpus-scale resource behavior, or production deployment.
