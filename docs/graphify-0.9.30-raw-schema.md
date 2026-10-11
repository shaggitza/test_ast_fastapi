# Graphify 0.9.30 raw schema support (offline adapter only)

The explicit selector `graphify-raw-0.9.30-v1` accepts the raw document
described by the pinned `graphify extract --code-only --no-cluster --out DIR`
source path. The established `node-link-v1` contract and behavior are
unchanged. The selector is available only with the explicit `--graphify`
overlay; neither path starts Graphify or installs/imports its package.

The raw document has exactly `nodes`, `edges`, `hyperedges`, `input_tokens`, and
`output_tokens`. The adapter bounds those arrays and counters, requires empty
hyperedges, rejects unsupported record fields and malformed provenance, checks
all referenced source paths against the selected project root, and validates
line markers against exact source bytes. Graph and source hashes are computed
from bounded reads; mutation checks and the exclusive receipt writer remain in
place. Raw line markers are never widened into byte or column ranges.

Raw `source` and `target` values are retained as producer endpoint order. That
does not establish a directed graph: the pinned producer's raw form is not the
directed NetworkX multigraph. In v2, only `calls`, `imports`, `imports_from`,
and `inherits` have source-confirmed orientation and can enter traversal.
`references`, `contains`, and all other relation names are retained with
`orientation="unknown"` and cannot fan out. All supplied `EXTRACTED`,
`INFERRED`, or `AMBIGUOUS` provenance labels remain separate from quality
confidence; the adapter does not promote them to HIGH/MEDIUM/LOW. Physical
records remain separate tuple entries, including repeated records. The
producer itself may already have deduplicated repeated tuples before writing.

This is an independently specified synthetic raw fixture contract, not an
observation of Graphify output. `tests/fixtures/graphify_0_9_30_raw_synthetic.json`
was not emitted by Graphify and must not be cited as producer-behavior evidence.
The release source artifacts and inspected file hashes are recorded in the
controlled-probe research at commit
`35cc919ef02b0a6570b95cda6425bbdf2a6a4c5f`, including
`benchmarks/providers/graphify_probe/evidence.json`. In that work, the official
`v0.9.30` source commit is
`ecfcd160d56b420eb8241430fa7b5b1951c7829f`; hashes identify the exact pinned
wheel and relevant source files. Graphify was not run or imported, and the
fixture remains synthetic.

The CLI/API selector does not close the trusted execution gate. GH101 runtime,
image, and policy receipts remain required before any real extraction. The
original GH110 gates also remain open: controlled positive and negative
fixtures, the frozen target/baseline corpus, calibration of provenance against
quality, and runtime/size/latency/resource measurements. This change makes no
ADOPT, HYBRID, or completed-GH110 claim.
