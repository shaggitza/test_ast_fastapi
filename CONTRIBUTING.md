# Contributing to FastAPI Endpoint Change Detector

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold this code.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- Make (optional, but recommended)

### Finding Issues to Work On

- Look for issues labeled `good first issue` for beginner-friendly tasks
- Issues labeled `help wanted` are actively seeking contributors
- Check the project board for prioritized work

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/fastapi-endpoint-detector.git
cd fastapi-endpoint-detector
```

### 2. Create Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install package in editable mode with development dependencies
pip install -e ".[dev]"

# Or using make
make install-dev
```

### 4. Install Pre-commit Hooks

```bash
pre-commit install
```

### 5. Verify Setup

```bash
# Run tests
pytest

# Run linting
ruff check .

# Run type checking
mypy src/
```

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-yaml-output` - New features
- `fix/handle-circular-imports` - Bug fixes
- `docs/update-cli-reference` - Documentation changes
- `refactor/simplify-ast-parser` - Code refactoring

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(parser): add support for APIRouter detection

fix(diff): handle file renames in unified diff format

docs(readme): add CI/CD integration examples
```

### Development Workflow

1. Create a branch from `main`
2. Make your changes
3. Add/update tests as needed
4. Ensure all tests pass
5. Update documentation if needed
6. Submit a pull request

## Pull Request Process

### Before Submitting

- [ ] All tests pass (`pytest`)
- [ ] Code is properly formatted (`ruff format .`)
- [ ] No linting errors (`ruff check .`)
- [ ] Type hints are complete (`mypy src/`)
- [ ] Documentation is updated
- [ ] Commit messages follow conventions

### PR Description

Include:
- **What**: Brief description of changes
- **Why**: Motivation and context
- **How**: Technical approach (if complex)
- **Testing**: How to verify the changes
- **Related Issues**: Link to related issues

### Review Process

1. Automated checks must pass
2. At least one maintainer approval required
3. All review comments must be addressed
4. Squash merge is preferred for clean history

## Coding Standards

### Python Style

We follow PEP 8 with some modifications enforced by ruff:

```python
# Good
def calculate_confidence(
    direct_deps: int,
    transitive_deps: int,
    *,
    threshold: float = 0.5,
) -> ConfidenceLevel:
    """Calculate confidence level for endpoint impact.
    
    Args:
        direct_deps: Number of direct dependencies changed.
        transitive_deps: Number of transitive dependencies changed.
        threshold: Minimum ratio for high confidence.
    
    Returns:
        Calculated confidence level.
    """
    ratio = direct_deps / (direct_deps + transitive_deps)
    if ratio >= threshold:
        return ConfidenceLevel.HIGH
    return ConfidenceLevel.MEDIUM
```

### Type Hints

All code must have complete type hints:

```python
# Required
def parse_diff(content: str) -> list[DiffHunk]:
    ...

# Collections should specify element types
def get_endpoints(app_file: Path) -> dict[str, Endpoint]:
    ...

# Use | for unions (Python 3.10+)
def find_handler(name: str) -> Handler | None:
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def analyze_changes(
    diff_path: Path,
    app_path: Path,
) -> AnalysisReport:
    """Analyze code changes and determine affected endpoints.
    
    This function orchestrates the full analysis pipeline, from
    parsing the diff file to generating the final report.
    
    Args:
        diff_path: Path to the unified diff file.
        app_path: Path to the FastAPI application entry point.
    
    Returns:
        Complete analysis report with affected endpoints.
    
    Raises:
        ParseError: If diff or app file cannot be parsed.
        ConfigurationError: If app file doesn't contain FastAPI app.
    
    Example:
        >>> report = analyze_changes(Path("changes.diff"), Path("main.py"))
        >>> print(report.affected_endpoints)
        [Endpoint(path="/users", method="GET"), ...]
    """
```

### Error Handling

Use custom exceptions and provide context:

```python
# Define specific exceptions
class ImportResolutionError(EndpointDetectorError):
    """Failed to resolve an import statement."""
    
    def __init__(self, import_name: str, search_paths: list[Path]) -> None:
        self.import_name = import_name
        self.search_paths = search_paths
        paths_str = ", ".join(str(p) for p in search_paths)
        super().__init__(
            f"Could not resolve import '{import_name}'. "
            f"Searched: {paths_str}"
        )

# Use them with context
try:
    module = resolve_import(import_name)
except ImportResolutionError:
    logger.warning(f"Skipping unresolvable import: {import_name}")
    continue
```

## Testing Guidelines

### Test Structure

```python
import pytest
from pathlib import Path

from fastapi_endpoint_detector.parser import FastAPIParser
from fastapi_endpoint_detector.models import Endpoint


class TestFastAPIParser:
    """Tests for FastAPI endpoint parsing."""
    
    def test_detects_simple_get_endpoint(self, tmp_path: Path) -> None:
        """Parser should detect @app.get decorated functions."""
        # Arrange
        source = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/users")
def get_users():
    return []
'''
        app_file = tmp_path / "main.py"
        app_file.write_text(source)
        
        # Act
        parser = FastAPIParser()
        endpoints = parser.parse(app_file)
        
        # Assert
        assert len(endpoints) == 1
        assert endpoints[0].path == "/users"
        assert endpoints[0].method == "GET"
    
    @pytest.mark.parametrize("method", ["get", "post", "put", "delete", "patch"])
    def test_detects_all_http_methods(
        self, 
        tmp_path: Path, 
        method: str,
    ) -> None:
        """Parser should detect all HTTP method decorators."""
        source = f'''
from fastapi import FastAPI
app = FastAPI()

@app.{method}("/resource")
def handler():
    pass
'''
        app_file = tmp_path / "main.py"
        app_file.write_text(source)
        
        parser = FastAPIParser()
        endpoints = parser.parse(app_file)
        
        assert len(endpoints) == 1
        assert endpoints[0].method == method.upper()
```

### Test Categories

- **Unit tests**: Test individual functions/methods in isolation
- **Integration tests**: Test component interactions
- **End-to-end tests**: Test complete CLI workflows

### Coverage Requirements

- Minimum 80% code coverage
- 100% coverage for core parsing logic
- All public APIs must be tested

## Documentation

### When to Update Docs

- Adding new features → Update relevant docs
- Changing CLI interface → Update cli-reference.md
- Changing configuration → Update configuration.md
- Bug fixes with workarounds → Update troubleshooting

### Documentation Structure

```
docs/
├── index.md              # Overview and navigation
├── getting-started.md    # Installation and quick start
├── cli-reference.md      # Complete CLI documentation
├── configuration.md      # Configuration options
├── architecture.md       # Technical deep-dive
└── ci-cd-integration.md  # CI/CD setup guides
```

### Writing Style

- Use clear, concise language
- Include code examples
- Explain "why", not just "what"
- Keep examples copy-pasteable

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue with reproduction steps
- **Features**: Open a GitHub Issue with use case description

Thank you for contributing! 🎉
