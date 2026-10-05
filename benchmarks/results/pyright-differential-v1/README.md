# Pyright differential typed-oracle timebox

Run from the repository root (Node.js 22 and Python 3.10+):

```sh
npm install --prefix /tmp/pyright-differential pyright@1.1.411
uv tool install mypy==2.4.0
uv tool install ruff==0.16.10
PYRIGHT=/tmp/pyright-differential/node_modules/.bin/pyright
for fixture in package_layout callable receiver overloads shadowing utf8; do
  python3 benchmarks/providers/pyright_differential.py "$fixture" --pyright "$PYRIGHT"
done
python3 benchmarks/providers/pyright_differential.py --verify-records
```

The harness analyzes only the six synthetic fixture directories under
`benchmarks/providers/fixtures/pyright_differential`. Per invocation it limits
inputs to 32 Python files, 256 KB of source, and 25 seconds per provider. Each
record captures source and config SHA-256 hashes, reported engine versions,
commands, elapsed time, diagnostics and mypy `reveal_type` observations.
Records are immutable: rerunning changed sources requires a new named fixture
and result record. Mocks are covered by unit tests and are not saved as provider
results.

Pyright 1.1.411 is pinned from the official Microsoft npm package/release. Its
official CLI contract documents `--outputjson`, diagnostic ranges and JSON
shape; this CLI does not offer a definition query. Consequently definition
targets and execution/reachability are explicit unsupported observations.
Diagnostics are compared only as error observations with a file/line/severity
and rule/message key. A missing diagnostic is not evidence of equivalence.
`reveal_type` text is preserved as a typed observation and is not conflated
with diagnostic agreement or runtime behavior. See the [official CLI
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
