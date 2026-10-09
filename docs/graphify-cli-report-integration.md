# GH110 Graphify CLI and report hook

Graphify is enabled explicitly with `--graphify`. It is a read-only diagnostic
overlay over operator-supplied snapshots and never replaces mypy/SCIP analysis
or changes endpoint candidates.

## Entry point

`analyze_graphify_overlay_from_inputs` accepts explicit baseline and target
Graphify snapshot paths, roots, schema selector, parsed `DiffFile` objects,
side-specific secure endpoints, and each side's canonical `SourceInventory`.
It validates both snapshots, scopes graph traversal to each inventory's exact
path and source-hash allowlist, maps removals to baseline coordinates and
additions to target coordinates, and builds route-handler plus declared-DI
seeds from secure endpoint records.

The adapter raises on missing, malformed, unsupported, or side-mismatched input.
An explicit CLI request should surface that failure as a CLI error; it should
not silently fall back to ordinary dependency analysis or claim Graphify
coverage. When the option is absent, current analysis and output stay unchanged.

## CLI contract and report boundary

`analyze --graphify` requires `--secure-ast`, an explicit `--baseline-app`,
`--graphify-baseline`, `--graphify-target`, and `--graphify-schema`. Supported
selectors are `node-link-v1` and `graphify-raw-0.9.30-v1`. Missing or malformed
inputs are explicit CLI errors; there is no fallback. Removed source ranges and
baseline endpoint seeds use the explicit baseline root, while additions and
target seeds use the target root.

The report adds a versioned `graphify_overlay` payload alongside the existing
analysis. It retains node IDs, edge orientation and key/context identity,
source paths, line spans, source hashes, package/version and schema metadata,
confidence provenance, and limitations. Overlay paths stay separate from
`affected_endpoints` and `candidate_endpoints`. All Graphify paths are LOW and
carry the limitation that they are lexical evidence only; `references` and
other relations do not establish execution or exact callable evidence.

Secure endpoint and declared-DI seeds are derived only from the existing
secure discovery records. Dependency occurrences retain a `binding_identity`
derived from their secure dependency `index_path`. Conditional inventories cap
those seeds at LOW; unresolved or spanless dependency identities are reported
without guessed bindings.

## Evidence limits

The committed Graphify fixtures are synthetic raw-schema inputs. The CLI accepts
operator-supplied graphs but does not run Graphify or claim they have trusted
GH101 receipts. This repository currently has no Graphify baseline/target
artifacts paired with the real-world corpus. Therefore this
branch can test the adapter contract and bounded traversal, but cannot report
Graphify extraction quality, corpus precision/recall, confidence calibration,
or production resource measurements. Those remain gated on trusted runtime
snapshots and a frozen, source-bound verification corpus.

The public CLI contract is also exercised with `CliRunner` against real secure
`ChangeMapper` analysis over temporary baseline and target source trees. Its
node-link snapshots are authenticated synthetic fixtures, not Graphify output.
The enabled case checks graph-byte hashes, source-byte bindings on both sides,
baseline removal and target addition routing, and that LOW lexical overlay
evidence remains outside endpoint candidate confidence. The disabled case
checks that ordinary JSON output omits `graphify_overlay` entirely. These tests
verify report wiring only; they do not establish Graphify extraction truth or
corpus precision.
