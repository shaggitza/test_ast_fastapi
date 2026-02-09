# FastAPI Endpoint Change Detector

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **An automation tool that analyzes Python code changes and identifies their impact on FastAPI endpoints**

## Overview

FastAPI Endpoint Change Detector is a CLI tool that leverages AST (Abstract Syntax Tree) parsing, static analysis tools (mypy, ruff), and code indexing to determine which API endpoints are affected by code changes in a FastAPI project.

This tool is designed for CI/CD pipelines to enable:
- **Targeted Testing**: Run only the tests related to changed endpoints
- **Impact Analysis**: Understand the blast radius of code changes
- **Documentation Updates**: Automatically identify which API docs need updating
- **Review Assistance**: Help reviewers understand which endpoints are affected by a PR

## Features

- 🔍 **AST-based Analysis**: Deep code parsing to trace function calls and dependencies
- 🔗 **Dependency Graph**: Build a complete dependency graph from endpoints to all related code
- 📊 **Diff Analysis**: Parse git diff files to identify changed code sections
- 🎯 **Endpoint Mapping**: Map changes back to specific FastAPI route handlers
- 🛠️ **Static Analysis Integration**: Leverage mypy and ruff for enhanced type and import analysis
- 📋 **Multiple Output Formats**: JSON, YAML, or human-readable reports

## Installation

```bash
pip install fastapi-endpoint-detector
```

Or install from source:

```bash
git clone https://github.com/your-org/fastapi-endpoint-detector.git
cd fastapi-endpoint-detector
pip install -e .
```

## Quick Start

```bash
# Basic usage
fastapi-endpoint-detector --app path/to/main.py --diff changes.diff

# With specific output format
fastapi-endpoint-detector --app path/to/main.py --diff changes.diff --format json

# Verbose output with dependency tree
fastapi-endpoint-detector --app path/to/main.py --diff changes.diff --verbose --show-tree
```

## CLI Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| `--app` | `-a` | Yes | Path to the FastAPI application entry file |
| `--diff` | `-d` | Yes | Path to the diff file containing code changes |
| `--format` | `-f` | No | Output format: `text`, `json`, `yaml` (default: `text`) |
| `--output` | `-o` | No | Output file path (default: stdout) |
| `--verbose` | `-v` | No | Enable verbose output |
| `--show-tree` | `-t` | No | Display full dependency tree |
| `--config` | `-c` | No | Path to configuration file |

## How It Works

1. **Parse FastAPI App**: Scans the application file to identify all route decorators (`@app.get`, `@app.post`, etc.) and their handler functions
2. **Build Dependency Graph**: Uses AST parsing to trace all function calls, imports, and dependencies from each endpoint
3. **Parse Diff File**: Analyzes the git diff to identify which files and functions have changed
4. **Map Changes to Endpoints**: Cross-references changed code with the dependency graph to determine affected endpoints
5. **Generate Report**: Outputs a report of all affected endpoints with confidence levels

## Example Output

```
FastAPI Endpoint Change Detector - Analysis Report
==================================================

Changes analyzed: 3 files, 12 functions modified

Affected Endpoints:
  ✓ GET  /api/users/{id}     [HIGH confidence]
    └── Changed: services/user_service.py::get_user_by_id
    └── Changed: models/user.py::User

  ✓ POST /api/users          [MEDIUM confidence]
    └── Changed: models/user.py::User (shared dependency)

  ? GET  /api/health         [LOW confidence]
    └── Changed: utils/helpers.py::format_response (indirect)

Unaffected Endpoints: 15
```

## Configuration

Create a `.endpoint-detector.yaml` file in your project root:

```yaml
# .endpoint-detector.yaml
app_patterns:
  - "app = FastAPI"
  - "application = FastAPI"

ignore_paths:
  - "tests/"
  - "migrations/"

confidence_threshold: medium  # low, medium, high

output:
  format: json
  include_unaffected: false
```

## Use Cases

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Detect affected endpoints
  run: |
    git diff ${{ github.event.before }}..${{ github.sha }} > changes.diff
    fastapi-endpoint-detector --app src/main.py --diff changes.diff --format json > affected.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: endpoint-impact
      name: Check endpoint impact
      entry: fastapi-endpoint-detector --app src/main.py --diff
      language: python
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - The modern Python web framework
- [mypy](https://mypy.readthedocs.io/) - Static type checker for Python
- [ruff](https://github.com/astral-sh/ruff) - Fast Python linter
