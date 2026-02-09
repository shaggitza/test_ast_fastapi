# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Mypy integration**: Added mypy's build API for type-aware dependency analysis
  - New `_get_module_dependencies_via_mypy()` method for full dependency graph extraction
  - New `_module_to_file_path()` helper for module resolution
  - Enhanced `_analyze_handler_with_types()` to leverage mypy's type system
- **Cache improvements**: Added cache loading/saving with progress reporting in `_preanalyze_coverage` and `_preanalyze_mypy`
- **Coverage backend initialization**: Coverage analyzer now properly initializes with progress feedback
- Test script `test_mypy_api.py` demonstrating mypy's build API usage

### Changed
- `coverage_analyzer` and `mypy_analyzer` properties no longer pre-analyze endpoints on initialization
- Pre-analysis moved to dedicated `_preanalyze_coverage` and `_preanalyze_mypy` methods with progress callbacks
- Updated documentation to reflect current project status and features
- Mypy is now a required dependency (>= 1.19.1)

---

## [0.1.0] - 2026-02-09

### Added
- CLI interface with three commands:
  - `analyze`: Analyze code changes and identify affected endpoints
  - `list`: List all FastAPI endpoints in the application
  - `deps`: Show dependency information for modules
- Three analysis backends:
  - `import`: Fast grimp-based import graph analysis (default)
  - `coverage`: AST tracing with code path analysis
  - `mypy`: Type-aware analysis using mypy's build API
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
