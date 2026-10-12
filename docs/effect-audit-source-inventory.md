# Effect audit source scope

The public `audit-effect-contracts` command obtains one configured `SourceInventory`. Its selected runtime Python paths are used by both secure AST and custom surface extraction; the same inventory and root are passed to Mypy. The endpoint inventory remains the distinct input to contract auditing.

`parser.include_patterns`, `parser.exclude_patterns`, `parser.follow_imports`, `parser.max_depth` and `analysis.include_test_endpoints` therefore govern this public audit path. Disabling `integrations.use_mypy` explicitly rejects typed contract auditing before either analyzer is constructed. An empty selection, unresolved local import, module collision or source-scope limitation prevents a complete contract audit.

Type stubs are declaration inputs, not executable endpoint evidence. In-root `.pyi` files never appear in the runtime inventory's `files` or `paths`. Selecting a stub through an include pattern reports an unsupported-scope limitation. An import that may use a local stub also records an unresolved edge and limitation, including a normal source/stub overlay. Unrelated stubs under the default runtime Python pattern do not broaden source scope. This change does not add a type-only input inventory.

The regression fixtures exercise public include/exclude scope, cold/warm report equality, disabled Mypy and incomplete-scope rejection, test-endpoint selection, and stub boundaries. Current read-only validation can check source, types and pure command wiring; filesystem fixtures require CI. These controls address part of GH284. Its provider disagreements, non-Python change evidence and remaining acceptance requirements stay open.
