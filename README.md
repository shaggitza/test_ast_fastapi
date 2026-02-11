# FastAPI Endpoint Change Detector

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **A CLI tool that analyzes Python code changes and identifies their impact on FastAPI endpoints**

## Overview

FastAPI Endpoint Change Detector is a CLI tool that analyzes code changes in FastAPI projects and determines which API endpoints are affected. It uses mypy for type-aware, precise dependency tracking from endpoints to all related code.

This tool is designed for CI/CD pipelines to enable:
- **Targeted Testing**: Run only the tests related to changed endpoints
- **Impact Analysis**: Understand the blast radius of code changes
- **Documentation Updates**: Automatically identify which API docs need updating
- **Review Assistance**: Help reviewers understand which endpoints are affected by a PR

## Features

- 🔍 **Type-Aware Analysis**: Uses mypy for precise dependency tracking
- 🔗 **Dependency Graph**: Build a complete dependency graph from endpoints to all related code
- 📊 **Diff Analysis**: Parse git diff files to identify changed code sections
- 🎯 **Endpoint Mapping**: Map changes back to specific FastAPI route handlers
- 💾 **Caching**: Cache analysis results for faster subsequent runs
- 📋 **Multiple Output Formats**: JSON, YAML, Markdown, HTML, or human-readable text reports
- 🎨 **Rich Progress Display**: Visual progress bars with real-time analysis feedback
- 🔎 **Interactive HTML Reports**: Hover over code references to see surrounding lines

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

For development with all dependencies:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Analyze Changes

```bash
# Basic usage - analyze a diff file against your FastAPI app
fastapi-endpoint-detector analyze --app path/to/main.py --diff changes.diff

# Output as JSON
fastapi-endpoint-detector analyze --app path/to/main.py --diff changes.diff --format json

# Output as Markdown
fastapi-endpoint-detector analyze --app path/to/main.py --diff changes.diff --format markdown

# Output as interactive HTML with hover tooltips
fastapi-endpoint-detector analyze --app path/to/main.py --diff changes.diff --format html -o report.html

# Save to file
fastapi-endpoint-detector analyze --app path/to/main.py --diff changes.diff -o report.txt
```

### List Endpoints

```bash
# List all endpoints in your FastAPI application
fastapi-endpoint-detector list --app path/to/main.py

# Output as JSON
fastapi-endpoint-detector list --app path/to/main.py --format json

# Output as Markdown table
fastapi-endpoint-detector list --app path/to/main.py --format markdown

# Output as interactive HTML table
fastapi-endpoint-detector list --app path/to/main.py --format html -o endpoints.html
```

## Commands

### `analyze` - Analyze Code Changes

Analyze a diff file and identify which FastAPI endpoints are affected.

```bash
fastapi-endpoint-detector analyze [OPTIONS]
```

| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `--app` | `-a` | Yes | Path to the FastAPI application entry file or directory |
| `--diff` | `-d` | Yes | Path to the diff file containing code changes |
| `--format` | `-f` | No | Output format: `text`, `json`, `yaml`, `markdown`, `html` (default: `text`) |
| `--output` | `-o` | No | Output file path (default: stdout) |
| `--app-var` | | No | Name of the FastAPI app variable (default: `app`) |
| `--verbose` | `-v` | No | Enable verbose output |
| `--no-cache` | | No | Disable caching of analysis results |
| `--clear-cache` | | No | Clear cached analysis data before running |
| `--config` | `-c` | No | Path to configuration file |

### `list` - List Endpoints

List all FastAPI endpoints discovered in the application.

```bash
fastapi-endpoint-detector list [OPTIONS]
```

| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `--app` | `-a` | Yes | Path to the FastAPI application entry file or directory |
| `--format` | `-f` | No | Output format: `text`, `json`, `yaml`, `markdown`, `html` (default: `text`) |
| `--output` | `-o` | No | Output file path (default: stdout) |
| `--app-var` | | No | Name of the FastAPI app variable (default: `app`) |

## How It Works

1. **Parse FastAPI App**: Scans the application to identify all route decorators (`@app.get`, `@app.post`, `@router.get`, etc.) and their handler functions

2. **Build Dependency Graph**: Uses mypy's type analysis to trace all function calls, imports, and dependencies from each endpoint with precise type-aware dependency resolution

3. **Parse Diff File**: Analyzes the git diff to identify which files and line ranges have changed

4. **Map Changes to Endpoints**: Cross-references changed code with the dependency graph to determine affected endpoints

5. **Generate Report**: Outputs a report of all affected endpoints with confidence levels and dependency chains

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
    fastapi-endpoint-detector analyze --app src/main.py --diff changes.diff --format json > affected.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: endpoint-impact
      name: Check endpoint impact
      entry: fastapi-endpoint-detector analyze --app src/main.py --diff
      language: python
```

## Project Status

This project is under active development. Current status:

- ✅ FastAPI endpoint extraction (app and router patterns)
- ✅ Mypy-based type-aware dependency analysis
- ✅ Diff parsing and change detection
- ✅ Change-to-endpoint mapping
- ✅ Multiple output formats (text, JSON, YAML)
- ✅ Caching for faster repeated analysis
- ✅ CLI with progress indicators
- 🔄 Configuration file support (partial)
- 📋 Planned: IDE integration
- 📋 Planned: Test selection output

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - The modern Python web framework
- [mypy](https://mypy.readthedocs.io/) - Static type checker for Python
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting
