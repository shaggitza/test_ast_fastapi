# FastAPI Endpoint Change Detector - Development Makefile
# ============================================================================

.PHONY: help install install-dev test test-cov lint format typecheck clean build docs serve-docs all check

# Default target
help:
	@echo "FastAPI Endpoint Change Detector - Development Commands"
	@echo "========================================================"
	@echo ""
	@echo "Setup:"
	@echo "  make install        Install package in production mode"
	@echo "  make install-dev    Install package with development dependencies"
	@echo ""
	@echo "Quality:"
	@echo "  make lint           Run ruff linter"
	@echo "  make format         Format code with ruff"
	@echo "  make typecheck      Run mypy type checker"
	@echo "  make check          Run all quality checks (lint + typecheck)"
	@echo ""
	@echo "Testing:"
	@echo "  make test           Run tests"
	@echo "  make test-cov       Run tests with coverage report"
	@echo "  make test-fast      Run tests excluding slow tests"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs           Build documentation"
	@echo "  make serve-docs     Serve documentation locally"
	@echo ""
	@echo "Build:"
	@echo "  make build          Build distribution packages"
	@echo "  make clean          Remove build artifacts"
	@echo ""
	@echo "Utilities:"
	@echo "  make all            Run check + test (CI pipeline)"
	@echo "  make pre-commit     Run pre-commit hooks on all files"

# ============================================================================
# Setup
# ============================================================================

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,analysis,docs]"
	pre-commit install

# ============================================================================
# Quality Checks
# ============================================================================

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

typecheck:
	mypy src/

check: lint typecheck
	@echo "✅ All quality checks passed!"

pre-commit:
	pre-commit run --all-files

# ============================================================================
# Testing
# ============================================================================

test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=src/fastapi_endpoint_detector --cov-report=html --cov-report=term-missing

test-fast:
	pytest tests/ -v -m "not slow"

test-integration:
	pytest tests/integration/ -v

# ============================================================================
# Documentation
# ============================================================================

docs:
	mkdocs build

serve-docs:
	mkdocs serve

# ============================================================================
# Build
# ============================================================================

build: clean
	python -m build

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf src/*.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# ============================================================================
# CI Pipeline
# ============================================================================

all: check test
	@echo "✅ CI pipeline passed!"

# ============================================================================
# Development Utilities
# ============================================================================

# Run the CLI with example data
example:
	fastapi-endpoint-detector \
		--app examples/sample_fastapi_project/main.py \
		--diff examples/diffs/service_change.diff \
		--verbose

# Show project statistics
stats:
	@echo "Lines of Code:"
	@find src/ -name "*.py" -exec cat {} + | wc -l
	@echo ""
	@echo "Test Files:"
	@find tests/ -name "*.py" | wc -l
	@echo ""
	@echo "Documentation Files:"
	@find docs/ -name "*.md" 2>/dev/null | wc -l || echo "0"
