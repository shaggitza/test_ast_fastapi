# GH110 Graphify 0.9.30 controlled probe status

**Decision: STOP extraction at this gate.** This directory records primary
source and PyPI artifact inspection, an independent fixture oracle, and the
reason no Graphify process was launched. It contains no extraction launcher;
tests here validate the fail-closed status and fixture definition only. The
JSON under `fixtures/` is expected behavior for a later trusted run, not
Graphify output or evidence of Graphify behavior.

## Pinned artifacts inspected

The official repository tag `v0.9.30` resolves to commit
`ecfcd160d56b420eb8241430fa7b5b1951c7829f` (tree
`c3a95cb81dd181b52e43d7874aa930808bed8bb3`). PyPI lists the same source
repository/tag in the release attestation. Downloaded release artifacts were
hashed locally, and package source files in the wheel byte-match the tagged
repository files.

| Artifact | SHA-256 |
|---|---|
| `graphifyy-0.9.30-py3-none-any.whl` | `bb614b7736d37d6a3c7ffe66d6edfff88b9582b066bdc9b27f0a07f6c8f5c58b` |
| `graphifyy-0.9.30.tar.gz` | `fe5f86be50b66f14ea74765bcf4d13d695d6d72b5a38b525075667fca6b37763` |
| upstream `pyproject.toml` | `9dd818130df8e07c47167c76aa56fd9ce5b5ee466d6c412a0b64705271285206` |
| repository `uv.lock` (no `graphifyy` entry) | `885ec5a2955af280fc814dec7389f9a291d5f89494e39cf5ed2f62a51018f2cb` |

Wheel source-file SHA-256 values, equal to their upstream tag counterparts:

| File | SHA-256 |
|---|---|
| `graphify/__main__.py` | `a388ae6c903eb8b753ed6afdd63e4258df3980e347b3441669f3d402e7ca7ccf` |
| `graphify/cli.py` | `855c3ef93a3441176cbfd9f6f6ebcec001b06308532620c1b4acc129412b8523` |
| `graphify/extract.py` | `2875f39ab80c0c1efe4f57f6ece3020ae2bdf1cc3776fbade6791b4bd39b1575` |
| `graphify/export.py` | `6320a1266bf1445dbac0c77ff153386e4ad332bcdd777199dad19fc976ad43c5` |
| `graphify/build.py` | `17eb81d317bfadd367c476ea58d18b6dca5e5c1c70ea997f60a5739b81ca6772` |

The wheel metadata declares `graphifyy==0.9.30`, the `graphify` console entry
point `graphify.__main__:main`, and a second `graphify-mcp` entry point. Source
implements `--version`/`-v` output as `graphify 0.9.30`. The command was not
run: the package was not installed or imported, and no trusted sandbox was
available. Thus this is source-derived version output, not executed version
evidence. The repo lock does not pin Graphify or its transitive dependencies.

## Interface and incompatibilities

Source inspection shows `graphify extract <path> --code-only --out <dir>` is a
real CLI form. `--code-only` drops all detected document, paper, and image files
from the semantic extraction pass. The code path calls the local AST extractor
on code files. It does not enable dedup LLM (`--dedup-llm` is a separate opt-in).
Extraction writes beneath `<out>/graphify-out`, including the graph, analysis,
build manifest/config, and marker files; a separate output root can keep writes
away from the fixture source mount. `extract` does not run the explicit `hook`,
`query`, `serve`, or `mcp` command branches. Query logging, HTTP/MCP serving,
and hook installation are distinct commands, not safety controls supplied by
`extract`.

| Safety concern | Pinned interface evidence | Probe decision |
|---|---|---|
| Semantic LLM/backend | `--code-only` empties the semantic document/paper/image set; with no `--dedup-llm`, the source computes `needs_llm` false. | Do not pass `--backend`; local code AST only is source-supported. |
| Docs/media | Detection classifies these inputs, but `--code-only` skips their semantic extraction. | Fixture is Python-only; verify corpus inventory in a future sandbox. |
| MCP/HTTP | `mcp`, `serve`, and `graphify-mcp` are separate command/entry-point paths. | Do not call these paths; there is no per-extract disable flag. |
| Query logs | Query commands are separate from `extract`. | Do not call query or result-saving commands; no logging disable flag exists on `extract`. |
| Hooks | Hook install/uninstall is a distinct command path. | Do not install/run hooks; no extraction flag controls hook state. |
| Repository writes | `extract` writes graph, analysis, manifest/config, and markers under `<out>/graphify-out`. | Future sandbox must mount source read-only and provide a separately pinned writable output mount. `--out` alone is not a filesystem boundary. |

These controls are source-path conclusions, not a tested security guarantee.
This research stage has no host command wrapper and performs no extraction.

The available output modes do not satisfy this repository's adapter contract:

* With `--no-cluster`, source writes raw extraction JSON with `nodes`, `edges`,
  `hyperedges`, and token counters. It is not NetworkX node-link JSON with
  `directed`, `multigraph`, `graph`, `nodes`, and `links`.
* Without `--no-cluster`, the CLI builds an undirected NetworkX graph by
  default. `export.to_json()` writes node-link `links` and restores the original
  endpoint IDs, but the top-level graph remains `directed: false` and
  `multigraph: false`. GH110's adapter requires both directed and multigraph
  modes.
* `graphify extract` does not parse `--directed`, `--multigraph`, `--no-label`,
  or `--no-viz`; its option loop silently skips unknown tokens. Extract itself
  writes no HTML and does not generate community labels. No documented or
  source-confirmed supported flag gives the required directed multigraph
  node-link contract.
* Source locations observed in the Python extractor are `L<number>` line
  markers. The pinned code does not serialize byte/column ranges for these
  Python calls, imports, methods, or inheritance edges. Byte and column spans
  cannot be assumed from line markers.

At source level, node IDs are generated by NFKC-normalizing names, replacing
runs of non-word characters with `_`, collapsing underscores, stripping edge
underscores, and case-folding. Extractor symbol IDs combine a normalized
repository-relative path stem with a symbol name; path components are retained.
The extraction post-pass canonicalizes path-derived IDs and disambiguates
collisions, so IDs should be treated as deterministic slugs under one scan,
not as globally stable symbol identities. The clustered graph is serialized
through NetworkX node-link data with `links`; edge `source` and `target` carry
the stored endpoint order. For `calls`, source is caller and target callee;
`inherits` uses subclass to base. This is source-level contract inspection,
not measured output from 0.9.30.

The serialized node-link document has top-level `directed`, `multigraph`,
`graph`, `nodes`, and `links`; the exporter adds `hyperedges` and may add
`built_at_commit`. Node-link IDs are the generated node `id` values, while
links reference them as `source` and `target`; links may include NetworkX's
multiedge `key`. Extracted node attributes include `id`, `label`, `file_type`,
`source_file`, and optional `source_location`. Edge attributes include
`relation`, `confidence`, `source_file`, `source_location`, and
`confidence_score`. Exact optional attributes vary by language and extractor.
The issue adapter applies a stricter allowlist and requires its own graph mode
and range/path constraints; upstream's broad graph schema alone does not
attest those constraints.

Consequently there is no confirmed invocation that both disables unwanted
behavior and produces the adapter's required directed graph format. Do not
work around this by inventing `--directed`, post-processing a raw graph as if
that were extraction evidence, or fabricating a graph/receipt. Other inspected
options: `--code-only`, `--no-cluster`, and `--out` are accepted by the
`extract` parser; `--backend`, `--model`, `--mode deep`, `--dedup-llm`,
`--google-workspace`, `--no-gitignore`, `--global`, `--postgres`, `--cargo`,
`--force`, `--allow-partial`, and resource tuning options are also recognized.
Only the first three are relevant to this proposed local controlled fixture
case. `--directed`, `--multigraph`, `--no-label`, and `--no-viz` are not
supported by `extract`; unknown arguments being silently ignored is itself a
reason to use only fixed, source-verified argv in any future runner.

## Host gate and evidence class

At inspection time Docker advertised only `runc` and
`io.containerd.runc.v2`; `runsc` was not on PATH. The independently verified
trusted runtime/image/policy receipts from issue #101 were unavailable. No
Graphify command, package code, project corpus, or fixture extraction was run.
Only ordinary archive hashing and textual source inspection were performed.

This closes no GH110 gate. The result is specifically **unsupported / STOP at
controlled extraction** pending (1) a compatible pinned Graphify interface or
reviewed adapter schema decision, and (2) the trusted #101 runtime, image, and
policy receipts. Do not treat the checked-in fixtures, source statements, or
unit tests as behavior evidence. Continue to preserve the offline adapter gate.

## Future independent fixture oracle

`fixtures/expectations.json` and both fixture trees define cases for later
trust-boundary execution: direct cross-file imported calls, imported aliases,
a locally stored alias invocation, methods, inheritance, import edges, UTF-8
byte-offset checks, and baseline-only deletion. The expected lines are
independent assertions for a future run. Since Graphify 0.9.30 source only
reports line markers, byte/column accuracy and range fidelity remain unproven.

Run the static-only guard tests with:

```sh
python3 -m unittest discover -s benchmarks/providers/graphify_probe -p 'test_*.py'
```

These tests never launch Graphify.

## Primary sources

* [Official Graphify v0.9.30 source tag](https://github.com/Graphify-Labs/graphify/tree/v0.9.30)
* [Pinned CLI implementation](https://github.com/Graphify-Labs/graphify/blob/v0.9.30/graphify/cli.py)
* [Pinned graph export implementation](https://github.com/Graphify-Labs/graphify/blob/v0.9.30/graphify/export.py)
* [Pinned Python extractor](https://github.com/Graphify-Labs/graphify/blob/v0.9.30/graphify/extract.py)
* [PyPI graphifyy 0.9.30 release and artifact hashes](https://pypi.org/project/graphifyy/0.9.30/)
* [GH110](https://github.com/shaggitza/test_ast_fastapi/issues/110) and [trusted sandbox gate GH101](https://github.com/shaggitza/test_ast_fastapi/issues/101)
