# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
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
