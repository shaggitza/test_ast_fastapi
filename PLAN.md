# Project Plan: FastAPI Endpoint Change Detector

## Executive Summary

This document outlines the development plan for a CLI tool that automatically detects which FastAPI endpoints are affected by code changes. The tool will parse Python code using AST, integrate with static analysis tools (mypy, ruff), and provide actionable insights for CI/CD pipelines.

---

## 1. Project Goals

### Primary Goal
Build an automation pipeline that identifies changes in Python code and maps them to affected FastAPI endpoints.

### Success Criteria
- [ ] Accurately detect 95%+ of direct endpoint dependencies
- [ ] Accurately detect 80%+ of indirect (transitive) dependencies
- [ ] Process a medium-sized FastAPI project (100+ endpoints) in under 30 seconds
- [ ] Provide clear, actionable output for CI/CD integration
- [ ] Zero false negatives for high-confidence changes

---

## 2. Core Components

### 2.1 FastAPI Application Parser
**Purpose**: Extract all endpoint definitions from a FastAPI application

**Responsibilities**:
- Identify FastAPI app instantiation patterns
- Parse route decorators (`@app.get`, `@router.post`, etc.)
- Extract endpoint metadata (path, methods, dependencies)
- Handle APIRouter includes and mounting
- Support multiple app patterns (single file, factory pattern, modular)

**Technical Approach**:
- Use Python's `ast` module for code parsing
- Build endpoint registry with full metadata
- Handle dynamic route registration patterns

### 2.2 Dependency Graph Builder
**Purpose**: Build a complete dependency graph from endpoints to all related code

**Responsibilities**:
- Trace function calls from endpoint handlers
- Resolve imports (relative, absolute, wildcard)
- Track class inheritance and method resolution
- Handle Dependency Injection (FastAPI `Depends()`)
- Index all symbols with file:line references

**Technical Approach**:
- Multi-pass AST analysis
- Symbol table construction
- Import resolution with fallback strategies
- Integration with mypy for type-aware analysis

### 2.3 Diff Parser
**Purpose**: Parse git diff files and extract structured change information

**Responsibilities**:
- Parse unified diff format
- Extract changed files, hunks, and line ranges
- Map line changes to function/class boundaries
- Handle file renames and deletions
- Support various diff sources (git, patch files)

**Technical Approach**:
- Implement unified diff parser
- Use AST to map line numbers to symbols
- Build change set with affected symbols

### 2.4 Change-to-Endpoint Mapper
**Purpose**: Correlate code changes with affected endpoints

**Responsibilities**:
- Query dependency graph for change impact
- Calculate confidence levels for each mapping
- Handle transitive dependencies
- Detect shared dependencies across endpoints
- Generate structured impact report

**Technical Approach**:
- Graph traversal algorithms (BFS/DFS)
- Confidence scoring based on dependency distance
- Caching for repeated queries

### 2.5 CLI Interface
**Purpose**: Provide user-friendly command-line interface

**Responsibilities**:
- Parse command-line arguments
- Validate inputs (file existence, format)
- Orchestrate analysis pipeline
- Format and output results
- Handle errors gracefully

**Technical Approach**:
- Use `argparse` or `click` for CLI parsing
- Implement multiple output formatters
- Progress indicators for long operations

---

## 3. Integration Points

### 3.1 mypy Integration
**Purpose**: Leverage type information for better dependency resolution

**Use Cases**:
- Resolve dynamically typed function calls
- Understand protocol/interface implementations
- Track type aliases and generic types

**Implementation**:
- Use mypy's programmatic API
- Cache type information for performance
- Fallback to AST-only when mypy unavailable

### 3.2 ruff Integration
**Purpose**: Fast import analysis and code quality checks

**Use Cases**:
- Rapid import graph construction
- Identify unused imports (noise reduction)
- Validate code before analysis

**Implementation**:
- Use ruff's JSON output mode
- Parse import information
- Integrate with dependency graph

### 3.3 Code Indexing
**Purpose**: Build searchable index of codebase symbols

**Index Contents**:
- Function definitions with signatures
- Class definitions with methods
- Import statements and aliases
- Variable assignments (module-level)
- Decorator applications

**Implementation**:
- SQLite or in-memory index
- Incremental index updates
- Symbol resolution APIs

---

## 4. Development Phases

### Phase 1: Foundation (Weeks 1-2)
- [ ] Project setup and tooling configuration
- [ ] Basic AST parsing infrastructure
- [ ] FastAPI endpoint extraction (simple cases)
- [ ] Unit test framework setup
- [ ] Example FastAPI project creation

**Deliverables**:
- Working endpoint parser for single-file apps
- Test suite with example fixtures
- CI pipeline setup

### Phase 2: Dependency Analysis (Weeks 3-4)
- [ ] Dependency graph data structures
- [ ] Import resolution system
- [ ] Function call tracing
- [ ] Basic diff parser

**Deliverables**:
- Complete dependency graph for simple projects
- Diff parsing with symbol mapping
- Integration tests

### Phase 3: Advanced Analysis (Weeks 5-6)
- [ ] FastAPI Depends() resolution
- [ ] APIRouter support
- [ ] Transitive dependency tracking
- [ ] mypy integration (optional enhancement)

**Deliverables**:
- Full FastAPI pattern support
- Accurate transitive dependency detection
- Performance benchmarks

### Phase 4: CLI & Output (Weeks 7-8)
- [ ] Full CLI implementation
- [ ] Multiple output formats (JSON, YAML, text)
- [ ] Configuration file support
- [ ] Error handling and reporting

**Deliverables**:
- Production-ready CLI
- Documentation
- Example CI/CD configurations

### Phase 5: Polish & Release (Weeks 9-10)
- [ ] Performance optimization
- [ ] Edge case handling
- [ ] Documentation completion
- [ ] PyPI packaging and release

**Deliverables**:
- Published package
- Complete documentation
- Release notes

---

## 5. Technical Decisions

### Language & Runtime
- **Python 3.10+**: Required for pattern matching and modern typing
- **Type Hints**: Full type coverage with mypy strict mode

### Dependencies
| Package | Purpose | Required |
|---------|---------|----------|
| `click` | CLI framework | Yes |
| `pydantic` | Data validation | Yes |
| `networkx` | Graph operations | Yes |
| `rich` | Terminal output | Yes |
| `pyyaml` | YAML support | Yes |
| `mypy` | Type analysis | Optional |
| `ruff` | Fast linting | Optional |

### Data Structures
- **Endpoint Registry**: Dict mapping paths to handler metadata
- **Dependency Graph**: NetworkX DiGraph with symbol nodes
- **Change Set**: Pydantic models for structured diff data
- **Impact Report**: Hierarchical structure with confidence scores

---

## 6. Testing Strategy

### Unit Tests
- AST parsing functions
- Diff parsing
- Graph operations
- Output formatters

### Integration Tests
- End-to-end analysis of example projects
- CLI argument handling
- File I/O operations

### Fixture Projects
- Simple single-file FastAPI app
- Modular FastAPI with routers
- Complex app with deep dependencies
- Edge cases (circular imports, dynamic routes)

---

## 7. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Dynamic code patterns | Incomplete detection | Document limitations, provide escape hatches |
| Performance on large codebases | Slow analysis | Incremental indexing, caching |
| False positives | Noise in output | Confidence scoring, filtering options |
| mypy compatibility | Feature degradation | Graceful fallback to AST-only |

---

## 8. Future Enhancements

- **IDE Integration**: VS Code extension for real-time impact analysis
- **Test Selection**: Output compatible with pytest markers
- **API Documentation**: Auto-update OpenAPI docs based on changes
- **Multi-framework Support**: Django, Flask adapters
- **Change Prediction**: ML-based change impact prediction

---

## 9. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Detection Accuracy | >90% | Manual verification on test projects |
| False Positive Rate | <10% | Noise ratio in outputs |
| Performance | <30s for 100 endpoints | Benchmark suite |
| Adoption | 100+ GitHub stars | Community engagement |

---

## Appendix: Example Use Cases

### Use Case 1: PR Impact Analysis
Developer opens PR modifying `services/user_service.py`. Tool identifies that `GET /users/{id}` and `POST /users` endpoints are affected, triggering targeted test runs.

### Use Case 2: Deployment Risk Assessment
Before deployment, tool analyzes all changes since last release and generates a report of all affected endpoints for review.

### Use Case 3: Documentation Maintenance
Tool identifies that `POST /orders` endpoint has changed parameters, flagging the API documentation for update.
