# Graphify code-graph POC boundary

Issue #110 evaluates Graphify as an optional generic code-graph provider. This
foundation is deliberately **not** connected to the default CLI or analyzer.
Mypy remains the only default semantic backend. Importing this project never
imports or installs Graphify, and missing Graphify tooling never causes fallback
or changes ordinary analysis.

## Pinned, explicit execution

The only attested tool is the separately installed PyPI package
`graphifyy==0.9.30`, whose console command reports exactly `graphify 0.9.30`.
Installation is an operator-controlled prerequisite outside the analyzed
checkout. `GraphifyRunner` takes the absolute executable path explicitly and
invokes this fixed argv shape without a shell:

```text
graphify extract <absolute-project-root> \
  --code-only --no-cluster --force --out <fresh-side-directory>
```

The runner:

- rejects every other tool version;
- strips API keys and proxy variables from the child environment;
- passes `--code-only`, so document/media semantic extraction is disabled;
- never passes backend, model, MCP/server, wiki, watch, hook, global-graph, or
  database flags;
- requires a fresh `baseline/` or `target/` directory outside the analyzed
  project and never overwrites it;
- uses a private HOME/config directory inside that snapshot directory;
- validates `graphify-out/graph.json` before publishing a deterministic
  `snapshot-receipt.json`.

This is process isolation, not a security sandbox. The Graphify executable still
reads source on the host. Do not use the POC on untrusted source until it is
placed behind the hardened runtime boundary.

## Supported `graph.json` contract

The adapter version is `1`, bound to Graphify 0.9.30's NetworkX node-link JSON:

| Level | Required contract |
|---|---|
| document | exactly `directed`, `multigraph`, `graph`, `nodes`, `links`, `hyperedges`, and optional `built_at_commit` |
| node | unique string `id`, string `label`, `file_type: code`, project-confined `source_file`, optional one-based `source_location` |
| link | existing `source` and `target` IDs, string `relation`, `confidence` in `EXTRACTED`, `INFERRED`, `AMBIGUOUS`, optional source span |
| semantic data | `hyperedges` must be empty |

Duplicate JSON members, non-finite numbers, invalid UTF-8, schema drift, dangling
edges, duplicate node IDs, non-code nodes, paths outside the project, malformed
or reversed ranges, oversized graphs, and unexpected fields fail closed.
`source_location` accepts `L12`, `12`, or an inclusive range such as `L12-L18`.

The adapter retains Graphify extraction strength separately from detector
confidence. It marks only source-backed `calls`, `imports`, `imports_from`,
`inherits`, `references`, and `re_exports` links as eligible for a future
traversal. `contains`, communities, similarity, natural-language relations, and
unknown relation types cannot become blast-radius evidence.

## Immutable snapshot receipt

The adapter reads one bounded byte snapshot, hashes those exact bytes with
SHA-256, then validates them. The exclusive receipt records:

- side (`baseline` or `target`);
- Graphify package version and adapter schema version;
- exact graph SHA-256;
- node and edge counts.

Baseline and target always occupy distinct fresh directories. A caller can pass
an expected SHA-256 when reopening a snapshot; a mismatch is an explicit error.

## Current decision and remaining gates

**Decision: BUILD the isolated adapter foundation; do not ADOPT the backend.**

Before an ADOPT or HYBRID decision, a later tranche must still:

1. verify Graphify 0.9.30 on controlled Python fixtures for aliases, methods,
   inheritance, imports/re-exports, deleted source, and cross-file calls;
2. overlay secure FastAPI handler/DI identity without modifying `graph.json`;
3. calibrate EXTRACTED/INFERRED/AMBIGUOUS edges against HIGH/MEDIUM/LOW policy;
4. run target and baseline corpus comparisons and report candidate gain, false
   positives, failures/abstentions, graph size, latency, and peak RSS;
5. prove no regression relative to mypy and record ADOPT, HYBRID, or STOP.

No community, proximity, semantic label, or natural-language query result may
satisfy these gates.
