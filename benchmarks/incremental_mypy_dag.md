# Typed incremental mypy provider

`MypyIncrementalProvider` is an opt-in build coordinator in
`fastapi_endpoint_detector.analyzer.mypy_incremental`. Its provider contract is
`BuildConfig` + canonical `{module_id: source_path}` inventory in,
`TypedBuild` + `BuildReport` out. `TypedBuild` retains mypy's graph, ASTs,
symbol tables, and exported expression type map for later analyzers.

The implementation uses the project lock's mypy 1.19.1 fine-grained API:
`mypy.build.build` creates the initial graph and
`mypy.server.update.FineGrainedBuildManager.update` retains typed state and
propagates changed triggers to dependent targets. Before every update it
flushes both mypy's AST cache and `FileSystemCache`, so same-path edits are
read from disk. Provider reports separate `cold_build`, `no_change_reuse`,
`incremental_update`, and `fallback_full_rebuild`.

Engine, mypy version, Python target, options, config file content, and canonical
source root are covered by the configuration fingerprint. Each report also
includes inventory and source-content cache fingerprints. A changed import
graph, changed module identities, moved module paths, or changed configuration
forces a full rebuild. This avoids stale import edges when mypy's public
fine-grained updater retains removed import bindings. A changed function
signature stays incremental: dependent typed targets are invalidated and
rechecked. Source diagnostics and updated/removed module IDs are included in
the report. The provider instance is mutable and should be owned by one build
session at a time.

The `typed_snapshot()` method is a correctness aid for trusted fixtures. It
serializes each retained mypy module AST and the types attached to call
expressions, allowing exact comparison with an independent fresh build.

Run five samples on the documented medium generated DAG:

```bash
uv sync --locked --extra dev
.venv/bin/python benchmarks/incremental_mypy_dag.py --modules 96 --samples 5
```

The medium fixture has 96 project modules, one typed function per module, and
a linear import and call chain. Each sample times a cold build, a no-change
reuse, a same-signature one-file edit, a signature edit that invalidates its
callers, and an import-retarget fallback. It uses only generated files and is
not a host-project corpus score. Raw timings are in
`benchmarks/results/gh283/typed-incremental-dag.json`.

Focused correctness coverage is in
`tests/unit/test_mypy_incremental_provider.py`. The default endpoint analyzer
does not use this provider yet; a follow-up integration must pass its exact
source inventory and effective mypy configuration, then consume `TypedBuild`
without rebuilding or discarding its retained type map.
