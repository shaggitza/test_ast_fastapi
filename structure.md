# Project Structure

This document describes the directory structure and file organization for the FastAPI Endpoint Change Detector project.

## Directory Tree

```
fastapi-endpoint-detector/
│
├── 📁 src/
│   └── 📁 fastapi_endpoint_detector/
│       ├── 📄 __init__.py                 # Package initialization, version info
│       ├── 📄 __main__.py                 # Entry point for `python -m` execution
│       ├── 📄 cli.py                      # CLI argument parsing and orchestration
│       ├── 📄 config.py                   # Configuration loading and validation
│       │
│       ├── 📁 parser/                     # Code parsing modules
│       │   ├── 📄 __init__.py
│       │   ├── 📄 ast_parser.py           # AST traversal and symbol extraction
│       │   ├── 📄 fastapi_parser.py       # FastAPI-specific endpoint parsing
│       │   ├── 📄 import_resolver.py      # Import statement resolution
│       │   └── 📄 diff_parser.py          # Git diff file parsing
│       │
│       ├── 📁 analyzer/                   # Analysis engine modules
│       │   ├── 📄 __init__.py
│       │   ├── 📄 dependency_graph.py     # Dependency graph construction
│       │   ├── 📄 endpoint_registry.py    # Endpoint storage and querying
│       │   ├── 📄 change_mapper.py        # Map changes to endpoints
│       │   └── 📄 confidence.py           # Confidence scoring logic
│       │
│       ├── 📁 output/                     # Output formatting modules
│       │   ├── 📄 __init__.py
│       │   ├── 📄 formatters.py           # Base formatter classes
│       │   ├── 📄 json_output.py          # JSON output formatter
│       │   ├── 📄 yaml_output.py          # YAML output formatter
│       │   └── 📄 text_output.py          # Human-readable text formatter
│       │
│       └── 📁 models/                     # Data models (Pydantic)
│           ├── 📄 __init__.py
│           ├── 📄 endpoint.py             # Endpoint data models
│           ├── 📄 dependency.py           # Dependency graph models
│           ├── 📄 diff.py                 # Diff/change models
│           └── 📄 report.py               # Analysis report models
│
├── 📁 tests/                              # Test suite
│   ├── 📄 __init__.py
│   ├── 📄 conftest.py                     # Pytest fixtures and configuration
│   │
│   ├── 📁 unit/                           # Unit tests
│   │   ├── 📄 __init__.py
│   │   ├── 📄 test_ast_parser.py
│   │   ├── 📄 test_fastapi_parser.py
│   │   ├── 📄 test_diff_parser.py
│   │   ├── 📄 test_dependency_graph.py
│   │   └── 📄 test_change_mapper.py
│   │
│   ├── 📁 integration/                    # Integration tests
│   │   ├── 📄 __init__.py
│   │   ├── 📄 test_cli.py
│   │   ├── 📄 test_end_to_end.py
│   │   └── 📄 test_output_formats.py
│   │
│   └── 📁 fixtures/                       # Test fixtures
│       ├── 📁 simple_app/                 # Simple single-file FastAPI app
│       ├── 📁 modular_app/                # Modular app with routers
│       ├── 📁 complex_app/                # Complex app with deep dependencies
│       └── 📁 diffs/                      # Sample diff files for testing
│
├── 📁 examples/                           # Example FastAPI projects
│   ├── 📄 README.md                       # Examples documentation
│   │
│   ├── 📁 sample_fastapi_project/         # Complete example FastAPI project
│   │   ├── 📄 main.py                     # FastAPI application entry point
│   │   ├── 📁 routers/                    # API routers
│   │   │   ├── 📄 __init__.py
│   │   │   ├── 📄 users.py
│   │   │   └── 📄 items.py
│   │   ├── 📁 services/                   # Business logic services
│   │   │   ├── 📄 __init__.py
│   │   │   ├── 📄 user_service.py
│   │   │   └── 📄 item_service.py
│   │   ├── 📁 models/                     # Pydantic models
│   │   │   ├── 📄 __init__.py
│   │   │   ├── 📄 user.py
│   │   │   └── 📄 item.py
│   │   ├── 📁 database/                   # Database layer
│   │   │   ├── 📄 __init__.py
│   │   │   └── 📄 connection.py
│   │   └── 📁 utils/                      # Utility functions
│   │       ├── 📄 __init__.py
│   │       └── 📄 helpers.py
│   │
│   └── 📁 diffs/                          # Example diff files
│       ├── 📄 simple_change.diff          # Single file change
│       ├── 📄 service_change.diff         # Service layer change
│       ├── 📄 model_change.diff           # Model change affecting multiple endpoints
│       └── 📄 multi_file_change.diff      # Complex multi-file change
│
├── 📁 docs/                               # Documentation
│   ├── 📄 index.md                        # Documentation home
│   ├── 📄 getting-started.md              # Quick start guide
│   ├── 📄 cli-reference.md                # CLI documentation
│   ├── 📄 configuration.md                # Configuration options
│   ├── 📄 architecture.md                 # Technical architecture
│   ├── 📄 ci-cd-integration.md            # CI/CD setup guides
│   └── 📁 api/                            # API documentation (auto-generated)
│
├── 📁 .github/                            # GitHub specific files
│   ├── 📄 copilot-instructions.md         # GitHub Copilot context
│   ├── 📁 workflows/                      # GitHub Actions
│   │   ├── 📄 ci.yml                      # Continuous Integration
│   │   ├── 📄 release.yml                 # Release automation
│   │   └── 📄 docs.yml                    # Documentation deployment
│   ├── 📁 ISSUE_TEMPLATE/                 # Issue templates
│   │   ├── 📄 bug_report.md
│   │   └── 📄 feature_request.md
│   └── 📄 PULL_REQUEST_TEMPLATE.md
│
├── 📄 README.md                           # Project README
├── 📄 PLAN.md                             # Development plan
├── 📄 structure.md                        # This file - project structure
├── 📄 CONTRIBUTING.md                     # Contribution guidelines
├── 📄 CHANGELOG.md                        # Version changelog
├── 📄 LICENSE                             # Apache 2.0 license
├── 📄 pyproject.toml                      # Project configuration (PEP 517/518)
├── 📄 .gitignore                          # Git ignore patterns
├── 📄 .pre-commit-config.yaml             # Pre-commit hooks configuration
├── 📄 .endpoint-detector.yaml             # Default tool configuration (example)
└── 📄 Makefile                            # Development task automation
```

## Module Descriptions

### Core Package (`src/fastapi_endpoint_detector/`)

| Module | Description |
|--------|-------------|
| `__init__.py` | Package metadata, version, public API exports |
| `__main__.py` | Enables `python -m fastapi_endpoint_detector` execution |
| `cli.py` | Command-line interface using Click framework |
| `config.py` | Configuration file loading, validation, defaults |

### Parser Package (`parser/`)

| Module | Description |
|--------|-------------|
| `ast_parser.py` | Core AST traversal, extracts functions, classes, imports |
| `fastapi_parser.py` | FastAPI-specific parsing: routes, routers, dependencies |
| `import_resolver.py` | Resolves import statements to file paths |
| `diff_parser.py` | Parses unified diff format, extracts change hunks |

### Analyzer Package (`analyzer/`)

| Module | Description |
|--------|-------------|
| `mypy_analyzer.py` | Mypy-based type-aware dependency analysis |
| `endpoint_registry.py` | Stores and queries endpoint metadata |
| `change_mapper.py` | Maps diff changes to affected endpoints |
| `confidence.py` | Calculates confidence scores for impact assessments |

### Output Package (`output/`)

| Module | Description |
|--------|-------------|
| `formatters.py` | Base formatter interface and utilities |
| `json_output.py` | JSON output formatter |
| `yaml_output.py` | YAML output formatter |
| `text_output.py` | Human-readable terminal output with colors |

### Models Package (`models/`)

| Module | Description |
|--------|-------------|
| `endpoint.py` | Endpoint, Route, Handler data classes |
| `dependency.py` | Symbol, DependencyNode, DependencyEdge |
| `diff.py` | DiffFile, Hunk, Change data classes |
| `report.py` | AnalysisReport, ImpactSummary data classes |

## Key Files

### Configuration Files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Project metadata, dependencies, tool configs |
| `.pre-commit-config.yaml` | Pre-commit hook definitions |
| `.endpoint-detector.yaml` | Default tool configuration example |
| `Makefile` | Development commands (test, lint, build) |

### Documentation Files

| File | Purpose |
|------|---------|
| `README.md` | Project overview and quick start |
| `PLAN.md` | Development roadmap and technical plan |
| `structure.md` | This file - explains project layout |
| `CONTRIBUTING.md` | How to contribute to the project |
| `CHANGELOG.md` | Version history and release notes |

### Example Files

The `examples/` directory contains a complete FastAPI application that serves as both documentation and test fixture. The accompanying diff files demonstrate various change scenarios.

## Naming Conventions

- **Packages**: `lowercase_with_underscores`
- **Modules**: `lowercase_with_underscores.py`
- **Classes**: `PascalCase`
- **Functions/Methods**: `snake_case`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Type Variables**: `T`, `K`, `V` or `TypeNameT`

## Import Structure

```python
# Standard library imports
import ast
from pathlib import Path

# Third-party imports
import click
from pydantic import BaseModel

# Local imports (relative within package)
from .parser import FastAPIParser
from .analyzer import DependencyGraph
from .models import Endpoint
```

## Test Organization

- **Unit tests**: One test file per module, testing individual functions
- **Integration tests**: Test complete workflows and CLI
- **Fixtures**: Shared test data in `tests/fixtures/`

Tests mirror the source structure:
- `src/fastapi_endpoint_detector/parser/ast_parser.py`
- → `tests/unit/test_ast_parser.py`
