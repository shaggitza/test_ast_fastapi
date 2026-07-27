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
- 🧭 **Bounded Receiver Analysis**: Adds LOW-only, source-proven constructor, alias,
  finite-factory, constructor-field, and exact-MRO propagation; dynamic or
  overflowing receiver sets fail closed
- 🔗 **Dependency Graph**: Build a complete dependency graph from endpoints to all related code
- 📊 **Diff Analysis**: Parse git diff files to identify changed code sections
- 🎯 **Endpoint Mapping**: Map changes back to specific FastAPI route handlers
- 🧭 **Effect Evidence**: Separate call reachability from returned, persisted, outbound,
  logged, internal, and unresolved data effects ([details](docs/effect-evidence.md))
- 📜 **Effect Contracts**: Strict data-only declarations and versioned Redis, MongoDB,
  filesystem, HTTP-client, and typed S3 presets for exact state and I/O symbols, with
  canonical provenance hashes and bounded hashed resource identities
  ([schema and presets](docs/effect-contracts.md))
- 🔗 **Resource Coupling**: Opt-in namespace-qualified writer/reader graphs over finite
  hashed identities, with report-only default and exact-callsite LOW candidate mode
  ([safety model](docs/resource-coupling.md))
- 🗄️ **SQL Transactions**: Distinguish staged ORM work, flush, reachable commit/rollback,
  and bounded same-scope lexical ordering without claiming durable persistence
  ([semantics](docs/sql-transactions.md))
- 🛰️ **Custom Surfaces**: Declarative execution-free entrypoints for message listeners,
  tools, tasks, schedulers, CLIs, and reactors ([schema](docs/custom-surfaces.md))
- 🔁 **Framework Semantics**: Exact lifecycle, middleware, background-task, and dependency
  callback boundaries without external-library fanout ([details](docs/framework-semantics.md))
- 💾 **Caching**: Cache analysis results for faster subsequent runs
- 📋 **Multiple Output Formats**: JSON, YAML, Markdown, HTML, or human-readable text reports
- 🎨 **Rich Progress Display**: Visual progress bars with real-time analysis feedback
- 🔎 **Interactive HTML Reports**: Hover over code references to see surrounding lines

## Installation

Install from source:

```bash
git clone https://github.com/shaggitza/test_ast_fastapi.git
cd test_ast_fastapi
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

# Use SCIP instead of mypy for reverse dependency analysis
fastapi-endpoint-detector analyze --app path/to/project --diff changes.diff --scip --secure-ast

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
| `--scip` | | No | Use SCIP reverse-impact analysis instead of mypy |
| `--baseline-app` | | No | Explicit baseline snapshot for removed SCIP lines (requires `--scip`) |
| `--secure-ast` | | No | Discover endpoints without importing application code |
| `--vm` | | No | Run an explicit isolated runtime comparator ([policy](docs/runtime-sandbox.md)) |
| `--app-entry` | | No | Exact secure-AST `MODULE:SYMBOL` app object or factory |
| `--bootstrap-entry` | | No | Exact secure-AST `MODULE:FUNCTION` registration bootstrap |
| `--config` | `-c` | No | Path to configuration file |

Without `--secure-ast` or `--vm`, endpoint discovery imports the application in
a fresh, time-bounded host subprocess. This isolates Python import state between
analyses, but it is **not a security sandbox**: application code still has the
host process's filesystem, environment, credential, device, and network access.
Use default runtime discovery only for trusted applications. The bounded host
subprocess currently requires POSIX; on other platforms use `--secure-ast` for
execution-free discovery or `--vm` for the hardened untrusted-code boundary.

`--vm` requires a prebuilt immutable image digest and a configured gVisor/Kata
runtime. It never builds an image or imports application code on the host; see
the [runtime sandbox policy](docs/runtime-sandbox.md).

`--scip` requires pinned external tools on `PATH`: `scip-query` 0.16.0,
`@sourcegraph/scip-python` 0.6.6, and SCIP CLI. Install Node tooling outside the
analyzed repository so it does not affect indexing:

```bash
mkdir -p ~/.local/share/fastapi-endpoint-detector-scip
cd ~/.local/share/fastapi-endpoint-detector-scip
npm install --omit=optional scip-query@0.16.0 @sourcegraph/scip-python@0.6.6
export PATH="$PWD/node_modules/.bin:$PATH"  # also add the SCIP CLI directory
```

`scip-python-plus` must not be visible because it missed dependency-injected
callers in validation. The command fails explicitly rather than silently
falling back to mypy. Added lines are indexed from `--app`; removed lines are
indexed from the explicit `--baseline-app` snapshot. If a diff removes Python
lines and no baseline is supplied, analysis fails explicitly rather than
inventing old source. Baseline discovery is always execution-free; target
discovery is execution-free when `--secure-ast` is supplied (as in the official
benchmark). `--app-entry` and `--bootstrap-entry` require `--secure-ast` and
never execute application code. Bootstrap interpretation is explicitly seeded,
bounded to project-local straight-line helpers, and records unsupported object
escape, mutation, control flow, or dynamic registration as conditional evidence;
no bootstrap/helper names are guessed. Dynamic behavior remains conservatively
unresolved.

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
| `--secure-ast` | | No | Discover endpoints without importing application code |
| `--vm` | | No | Run the explicit hardened runtime comparator |

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
parser:
  include_patterns: ["**/*.py"]
  exclude_patterns: ["**/tests/**", "**/migrations/**"]
  max_depth: 10
analysis:
  confidence_threshold: 0.5
  effect_contracts: effects.yaml       # optional, config-relative
  surface_contracts: surfaces.yaml     # optional, requires --secure-ast
  # surface_preset: event-listeners-v1 # alternatives: mcp-v1, workers-v1, framework-v1
output:
  show_confidence: true
  show_dependency_chain: false
integrations:
  use_mypy: true
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

Mypy retains large semantic graphs during analysis-heavy tests. Run the suite in
isolated per-file processes to keep peak RAM bounded and stop before low-memory or
low-disk conditions can destabilize a development host:

```bash
.venv/bin/python scripts/run_tests_bounded.py
```

Additional pytest arguments can be repeated with `--pytest-arg`. The runner uses
argv-only subprocesses, private temporary directories, a 15-minute per-file timeout,
and removes only local mypy/pytest caches between files. It rejects paths outside the
repository and terminates only a timed-out test's private process group. It never
prunes Docker images, volumes, or shared system data.

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - The modern Python web framework
- [mypy](https://mypy.readthedocs.io/) - Static type checker for Python
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting
