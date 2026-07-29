# Graphify code-graph POC boundary

Issue #110 evaluates Graphify as an optional generic code-graph provider. This
foundation is deliberately **not** connected to the default CLI or analyzer.
Mypy remains the only default semantic backend. Importing this project never
imports, installs, or executes Graphify, and missing Graphify tooling never
causes fallback or changes ordinary analysis.

## Offline-only foundation

The adapter accepts only an operator-supplied `graph.json`. It performs bounded,
execution-free validation and can exclusively create a deterministic import
receipt. There is no extraction launcher or ordinary host subprocess path.
Graphify execution, including enforced no-network operation and a read-only
source mount, is deferred to the trusted hardened sandbox gate tracked by
[#101](https://github.com/shaggitza/test_ast_fastapi/issues/101). Do not run
Graphify against a checkout through an ad hoc host subprocess.

The expected producer metadata is pinned as:

| Item | Expected value |
|---|---|
| PyPI distribution | `graphifyy` |
| distribution version | `0.9.30` |
| console command | `graphify` |
| exact version output | `graphify 0.9.30` |
| adapter schema | `1` |

These are **expected provenance metadata**, not proof that an imported file was
created by that executable. The future sandbox gate must attest the installed
artifact and invocation before passing its output to this importer. The adapter
does not install the package or call the command to obtain self-reported
metadata.

## Supported `graph.json` contract

The offline adapter is bound to the frozen, directed NetworkX node-link shape:

| Level | Required contract |
|---|---|
| document | exactly required `directed`, `multigraph`, `graph`, `nodes`, `links`, `hyperedges`, plus optional `built_at_commit` |
| graph mode | `directed: true`, `multigraph: true`, empty `graph`, empty `hyperedges` |
| node | unique string `id`, string `label`, `file_type: code`, non-empty project-confined regular `source_file`, optional bounded `source_location` |
| link | existing `source` and `target` IDs, an explicitly oriented relation, `confidence` in `EXTRACTED`, `INFERRED`, `AMBIGUOUS`, optional bounded source occurrence |

The attested relation orientation is always the JSON `source` ID to the JSON
`target` ID:

| Relation | Orientation |
|---|---|
| `calls` | caller to callee |
| `imports`, `imports_from` | importer to imported symbol/module |
| `inherits` | subclass to base |
| `references` | referencer to referenced symbol |
| `re_exports` | exporter to exported symbol |
| `contains` | container to contained node |
| `related_to` | symmetric; never traversal evidence |

Relations without a pinned orientation fail closed. Only source-backed `calls`,
`imports`, `imports_from`, `inherits`, `references`, and `re_exports` may be
eligible for future traversal. `contains`, similarity, community data, and
natural-language relations cannot become blast-radius evidence.

All allowlisted fields are validated. Former unchecked fields such as nested
`metadata`, origin/target hints, scopes, package, and namespace are rejected.
Duplicate JSON members, non-finite numbers, invalid UTF-8, schema drift,
dangling edges, duplicate node IDs, non-code nodes, paths outside the project,
malformed/reversed/out-of-file ranges, oversized files, non-regular files, and
mutation during import fail closed. `source_location` accepts `L12`, `12`, or an
inclusive range such as `L12-L18`.

## Bounded exact-byte provenance and receipt

`graph.json` is opened once, required to be a regular file, and read through
that descriptor with a `MAX_GRAPH_BYTES + 1` bound. Descriptor/path identity,
size, and timestamp checks detect replacement or mutation during the read. The
SHA-256 is computed over those exact bytes.

Each referenced source file is similarly confined, opened as a regular file,
and read at most once with a `MAX_SOURCE_BYTES + 1` bound. Node and edge line
occurrences must fit those exact bytes. Source SHA-256 values are retained on
nodes and spans, and all source snapshots are checked again before import
returns.

`import_graphify_snapshot()` exclusively creates a receipt containing:

- side (`baseline` or `target`);
- graph SHA-256 and adapter schema version;
- pinned **expected** Graphify package/version/command/version-output metadata;
- attested directed/multigraph values;
- node and edge counts;
- explicit `offline-only` import mode.

A caller may require an expected lowercase SHA-256 when importing. Graph,
project, source, and receipt path failures are normalized to
`GraphifyAdapterError`.

## Current decision and remaining gates

**Decision: BUILD the offline adapter foundation; do not ADOPT or invoke the
backend. Keep #110 open.**

Before an ADOPT or HYBRID decision, later work must still:

1. use the trusted #101 sandbox gate to enforce no network, a read-only source
   mount, resource bounds, and pinned executable/package identity;
2. verify real Graphify 0.9.30 artifacts on controlled Python fixtures for
   direction, ranges, aliases, methods, inheritance, imports/re-exports,
   deleted source, and cross-file calls;
3. overlay secure FastAPI handler/DI identity without modifying `graph.json`;
4. calibrate EXTRACTED/INFERRED/AMBIGUOUS edges against HIGH/MEDIUM/LOW policy;
5. run target and baseline corpus comparisons and report candidate gain, false
   positives, failures/abstentions, graph size, latency, and peak RSS;
6. prove no regression relative to mypy and record ADOPT, HYBRID, or STOP.

No community, proximity, semantic label, or natural-language query result may
satisfy these gates. This foundation makes no LLM, server, or network request;
its stronger no-network execution guarantee remains deferred because it does
not execute Graphify at all.
