# Graphify 0.9.30 raw schema support

The adapter has an explicit `schema="graphify-raw-0.9.30-v1"` selector for
the raw document emitted by the pinned `graphify extract --code-only
--no-cluster --out DIR` path. The existing `node-link-v1` selector remains
strict and unchanged. The raw top level is exactly `nodes`, `edges`,
`hyperedges`, `input_tokens`, and `output_tokens`; this parser rejects extra or
missing top-level keys, invalid counters, nonempty hyperedges, unsupported
record fields, invalid provenance, missing endpoints, duplicate IDs, and
ambiguous repeated `(source, target, relation)` edges.

Raw edge `source` and `target` order is retained for known semantic relations.
The adapter maps `calls` to caller-to-callee, `imports` and `imports_from` to
importer-to-imported, `inherits` to subclass-to-base, and `references` to
referencer-to-referenced. `confidence` carries Graphify provenance
(`EXTRACTED`, `INFERRED`, or `AMBIGUOUS`); it is not a HIGH/MEDIUM/LOW quality
rating. Other relation names fail closed. Raw `source_location` is line-only
(`L<number>` or a line range where the adapter already permits it); the
adapter stores those as line spans and never infers byte, column, or function
end positions.

The adapter's normalized raw snapshots record directed semantic edges while
reporting `multigraph=false`: Graphify's raw merge deduplicates edge tuples and
does not provide a directed multigraph contract. It can therefore lose
repeated same-relation evidence in extraction before this adapter sees it.
This support removes the node-link format gate for imports; it is not evidence
that a Graphify extraction ran or that the result meets GH110 quality goals.

## Pinned upstream source evidence

The upstream release is `graphifyy==0.9.30`, official tag `v0.9.30`, commit
`ecfcd160d56b420eb8241430fa7b5b1951c7829f`; the primary inspected files are
[`graphify/cli.py`](https://github.com/Graphify-Labs/graphify/blob/v0.9.30/graphify/cli.py)
and [`graphify/extract.py`](https://github.com/Graphify-Labs/graphify/blob/v0.9.30/graphify/extract.py).
The CLI accepts `--code-only`, `--no-cluster`, and `--out`; the no-cluster
writer serializes the raw merged object with `nodes`, `edges`, `hyperedges`,
`input_tokens`, and `output_tokens`. The extractor emits node IDs, labels,
`file_type`, `source_file`, optional `source_location`; edge endpoints,
`relation`, provenance `confidence`, `source_file`, line `source_location`,
and `weight`, with optional context and extractor-specific attributes.
Source locations are line markers. The clustered exporter creates an
undirected graph by default, and the extract command has no supported
directed/multigraph flag. The adapter does not use clustered edges to infer
semantic direction.

The fixture [`graphify_0_9_30_raw_synthetic.json`](../tests/fixtures/graphify_0_9_30_raw_synthetic.json)
is independently constructed from that source-described shape. It is labeled
synthetic by this documentation and test name; it is not Graphify output or
tool-behavior evidence. Graphify was not installed, imported, or run. GH101's
trusted gVisor/Kata runtime remains unavailable, so runtime receipts, real
baseline/target corpus extraction, CLI calibration, and quality acceptance
remain open. GH110 remains open.
