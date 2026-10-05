# GH110 Graphify CLI and report hook

This document describes the additive hook supplied by
`analyzer.graphify_report_adapter`. The implementation in this branch does not
change CLI, mapper, or report owner files.

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

## Proposed PR #312 hook

1. Add an explicit `--graphify` option and require operator-supplied baseline
   and target snapshot paths plus an explicit schema selector.
2. Extend `AnalysisReport` with `graphify_overlay: GraphifyOverlayReport | None`
   and expose it in the JSON formatter. Keep it separate from
   `affected_endpoints` and `candidate_endpoints`.
3. After parsing the diff and discovering the baseline/target endpoint
   inventories, call `analyze_graphify_overlay_from_inputs`; attach the result
   with `attach_graphify_overlay`. Prefer passing the mapper's existing
   `DiffFile` tuple through a report-enricher seam so coordinates are not
   reparsed or widened.
4. Preserve route identity through the public endpoint identifier and exact
   secure handler source range. Declared dependency occurrences use a separate
   `binding_identity` derived from their secure dependency `index_path`.
   Conditional inventories cap those seeds at LOW; unresolved or spanless
   dependency identities are recorded as limitations and never guessed.

Each path record carries snapshot side, canonical module/path/source hash,
directed relation orientation, physical edge key and context identity,
extractor strength, overlay confidence, per-path incompleteness, and
limitations. The payload explicitly identifies itself as evidence from
validated offline snapshots only. It does not assert execution or alter the
legacy affected-endpoint score.

## Evidence limits

The committed Graphify fixtures are synthetic raw-schema inputs. This
repository currently has no trusted GH101 Graphify receipts or Graphify
baseline/target artifacts paired with the real-world corpus. Therefore this
branch can test the adapter contract and bounded traversal, but cannot report
Graphify extraction quality, corpus precision/recall, confidence calibration,
or production resource measurements. Those remain gated on trusted runtime
snapshots and a frozen, source-bound verification corpus.
