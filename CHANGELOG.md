# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Cached endpoint call sites are reused only when freshly rebuilt dependency typing and distribution metadata still match the cache fingerprint.
- Applicability provenance now records metadata by distribution name and exact adjacent path, handles package initializers by their actual relative paths, and checks Python-only source pins against the target interpreter version.
- Attached contract evidence carries the same applicability status as its embedded audit; empty source-hash defaults no longer alter hashes for existing unpinned contracts.

### Added
- Added exact Motor 3.6.0 insert, update, and delete bindings to MongoDB preset 1.1.0. The vendor source proof is pinned to wheel SHA-256 `9f07ed96f1754963d4386944e1b52d403a5350c687edc60da487d66f98dbf894`; `motor/core.pyi` SHA-256 `648fa05c34b81d6510b0cc672ac041e9ebfbb88c7ffbb5573e6d40c8571dcde0`, `motor/motor_asyncio.pyi` SHA-256 `6103c4af1c7c81ba3f7bccbfb478f897982eb0e38fef6592a111a22e41eee736`, and `motor/py.typed` SHA-256 `cf044d8d9395de5785cc67707e46ef18e7c66c1a2994879e66ee20edde8ff76f`.
- Extended the bounded Motor probe to snapshot `.pyi` declarations and `py.typed` markers from hash-pinned wheels without importing Motor or PyMongo.

### Changed
- Bumped the MongoDB preset to 1.2.0 (revision 3) for enforced Motor package evidence.
- Pinned Motor 3.6.0 wheel `METADATA` SHA-256 `dce8b401625d673eed6b2c0c66d9d196a13de0649c0788da8b3e2a72edb2965d` alongside declaration source hashes.
- Motor bindings now require the parsed Motor 3.6.0 declaration hashes and the exact hash of its wheel `METADATA`; the audit records target source and version evidence and leaves missing or mismatched evidence unmatched.
- **Simplified to mypy-only analysis**: Removed `import` (grimp-based) and `coverage` analysis backends
  - Removed `dependency_graph.py` module and grimp dependency
  - Removed `coverage_analyzer.py` module and coverage.py dependency
  - Removed `--backend` CLI option - mypy is now the only analysis method
  - Updated `ChangeMapper` to use mypy exclusively
  - Removed `use_ruff` configuration option
  - Updated all documentation to reflect mypy-only analysis

### Removed
- Import-based backend using grimp
- Coverage-based backend using AST tracing
- `--backend` CLI option
- `deps` CLI command (depended on import graph)
- grimp dependency
- coverage.py dependency

### Added
- **Reviewed exact effect preset rows**: added four filesystem, five Motor,
  and five typed-S3 declarations with bounded source metadata. HTTPX module rows
  remain held pending approval of the module-mutation guard. Requests module
  helpers remain open.
- **Mypy integration**: Added mypy's build API for type-aware dependency analysis
  - New `_get_module_dependencies_via_mypy()` method for full dependency graph extraction
  - New `_module_to_file_path()` helper for module resolution
  - Enhanced `_analyze_handler_with_types()` to leverage mypy's type system
- **Cache improvements**: Added cache loading/saving with progress reporting in `_preanalyze_mypy`
- Test script `test_mypy_api.py` demonstrating mypy's build API usage

---

## [0.1.0] - 2026-02-09

### Added
- CLI interface with three commands:
  - `analyze`: Analyze code changes and identify affected endpoints
  - `list`: List all FastAPI endpoints in the application
  - `deps`: Show dependency information for modules
- Mypy-based type-aware dependency analysis
- FastAPI endpoint parser supporting:
  - Direct `@app` decorators (`@app.get`, `@app.post`, etc.)
  - `@router` decorators with `APIRouter`
  - Router includes with prefix support
- AST-based dependency graph construction
- Unified diff file parser
- Change-to-endpoint mapping with confidence levels
- Output formats: text, JSON, YAML
- Caching system for faster repeated analysis
- Rich progress display with real-time feedback
- Configuration file support (`.endpoint-detector.yaml`)
- Example FastAPI project with sample diffs
- Comprehensive test suite
- Full documentation

---

## [Unreleased]

### Changed
- Enforce Motor preset applicability against the exact Motor 3.6.0 typed declaration bytes parsed by mypy. Missing, changed, or unverified declaration sources leave calls unmatched with `package_applicability_unverified`.
- The effect audit CLI and change mapper now report when exact typed-source applicability pins were evaluated.

## Version History Template

When releasing a new version, copy this template:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Features that will be removed in future versions

### Removed
- Features removed in this version

### Fixed
- Bug fixes

### Security
- Security-related changes
```

---

[Unreleased]: https://github.com/your-org/fastapi-endpoint-detector/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/fastapi-endpoint-detector/releases/tag/v0.1.0
