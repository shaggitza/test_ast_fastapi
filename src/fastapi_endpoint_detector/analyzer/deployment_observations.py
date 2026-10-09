"""Finite source observations for deployment configuration and subprocesses.

The recognizers never expand variables, evaluate shell commands, or execute
repository content. Unknown/dynamic values are retained as uncertainty records.
"""

from __future__ import annotations

import ast
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_ROUTE_ENV_KEYS = frozenset(
    {
        "API_BASE_URL",
        "API_URL",
        "BASE_PATH",
        "FASTAPI_ROOT_PATH",
        "HOST",
        "NEXT_PUBLIC_API_URL",
        "PORT",
        "PUBLIC_API_URL",
        "ROOT_PATH",
        "VITE_API_BASE_URL",
        "WEBSOCKET_URL",
        "WS_URL",
    }
)
_DYNAMIC_ENV = re.compile(r"\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)")
_INSTRUCTIONS = frozenset({"ENV", "EXPOSE", "ENTRYPOINT", "CMD"})
_SUBPROCESS_CALLS = frozenset({"run", "Popen", "call", "check_call", "check_output"})


@dataclass(frozen=True)
class DeploymentObservation:
    """One literal deployment or process-launch fact from source."""

    source_path: Path
    line: int
    kind: str
    key: str | None
    value: str | tuple[str, ...] | None
    certainty: str
    uncertainty: str | None = None


def _env_value(path: Path, line: int, key: str, value: str) -> DeploymentObservation:
    if key.upper() not in _ROUTE_ENV_KEYS:
        return DeploymentObservation(
            path,
            line,
            "environment",
            key,
            None,
            "uncertain",
            "value not in route configuration allowlist",
        )
    unquoted = value.strip()
    if len(unquoted) >= 2 and unquoted[0] == unquoted[-1] and unquoted[0] in "'\"":
        unquoted = unquoted[1:-1]
    if _DYNAMIC_ENV.search(unquoted):
        return DeploymentObservation(
            path, line, "environment", key, None, "uncertain", "value contains variable expansion"
        )
    if "URL" in key.upper():
        try:
            parsed = urlsplit(unquoted)
        except ValueError:
            parsed = None
        if parsed is not None and (
            parsed.username or parsed.password or parsed.query or parsed.fragment
        ):
            return DeploymentObservation(
                path,
                line,
                "environment",
                key,
                None,
                "uncertain",
                "URL contains credentials or query/fragment data",
            )
    return DeploymentObservation(path, line, "environment", key, unquoted, "exact")


def extract_env_observations(
    source: str, source_path: Path | str = ".env"
) -> tuple[DeploymentObservation, ...]:
    """Observe simple KEY=value lines; never expand values or expose non-route values."""
    path = Path(source_path)
    observations: list[DeploymentObservation] = []
    for line_number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key.strip()):
            continue
        observations.append(_env_value(path, line_number, key.strip(), value.strip()))
    return tuple(observations)


def _docker_logical_lines(source: str) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    pending = ""
    start_line = 0
    for number, physical in enumerate(source.splitlines(), 1):
        text = physical.rstrip()
        if not pending:
            start_line = number
        if text.endswith("\\"):
            pending += text[:-1] + " "
            continue
        logical.append((start_line, pending + text))
        pending = ""
    if pending:
        logical.append((start_line, pending))
    return logical


def extract_dockerfile_observations(  # noqa: PLR0912
    source: str, source_path: Path | str = "Dockerfile"
) -> tuple[DeploymentObservation, ...]:
    """Observe route-relevant ENV, exposed ports, and exec-form startup argv."""
    path = Path(source_path)
    observations: list[DeploymentObservation] = []
    for line_number, raw in _docker_logical_lines(source):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        instruction, _, argument = text.partition(" ")
        instruction = instruction.upper()
        if instruction not in _INSTRUCTIONS:
            continue
        argument = argument.strip()
        if instruction == "ENV":
            try:
                parts = shlex.split(argument, comments=False, posix=True)
            except ValueError:
                observations.append(
                    DeploymentObservation(
                        path, line_number, "environment", None, None, "uncertain", "malformed ENV"
                    )
                )
                continue
            pairs: list[tuple[str, str]] = []
            if parts and all("=" in part for part in parts):
                for part in parts:
                    key, _, value = part.partition("=")
                    pairs.append((key, value))
            elif len(parts) >= 2 and "=" not in parts[0]:
                pairs.append((parts[0], " ".join(parts[1:])))
            elif parts:
                observations.append(
                    DeploymentObservation(
                        path, line_number, "environment", None, None, "uncertain", "malformed ENV"
                    )
                )
            for key, value in pairs:
                observations.append(_env_value(path, line_number, key, value))
        elif instruction == "EXPOSE":
            try:
                ports = shlex.split(argument, comments=False, posix=True)
            except ValueError:
                ports = []
            for port in ports:
                if re.fullmatch(r"[0-9]+(?:/(?:tcp|udp|sctp))?", port, re.IGNORECASE):
                    observations.append(
                        DeploymentObservation(
                            path, line_number, "exposed_port", None, port.lower(), "exact"
                        )
                    )
                else:
                    observations.append(
                        DeploymentObservation(
                            path,
                            line_number,
                            "exposed_port",
                            None,
                            None,
                            "uncertain",
                            "dynamic or malformed port",
                        )
                    )
        elif argument.startswith("["):
            try:
                argv = json.loads(argument)
            except json.JSONDecodeError:
                argv = None
            if isinstance(argv, list) and all(isinstance(item, str) for item in argv):
                observations.append(
                    DeploymentObservation(
                        path,
                        line_number,
                        "container_argv",
                        instruction.lower(),
                        tuple(argv),
                        "exact",
                    )
                )
            else:
                observations.append(
                    DeploymentObservation(
                        path,
                        line_number,
                        "container_argv",
                        instruction.lower(),
                        None,
                        "uncertain",
                        "invalid exec-form command",
                    )
                )
        else:
            observations.append(
                DeploymentObservation(
                    path,
                    line_number,
                    "container_argv",
                    instruction.lower(),
                    None,
                    "uncertain",
                    "shell-form command is not interpreted",
                )
            )
    return tuple(observations)


def _literal_argv(node: ast.AST) -> tuple[str, ...] | None:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    values: list[str] = []
    for item in node.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            return None
        values.append(item.value)
    return tuple(values)


@dataclass
class _PythonScope:
    kind: str
    parent: _PythonScope | None
    local_names: set[str]
    writes: set[str]
    globals: set[str]
    nonlocals: set[str]
    imports: dict[str, list[tuple[int, tuple[str, str] | None, bool]]]


class _ScopeBindings(ast.NodeVisitor):
    """Collect one Python scope without leaking nested imports or locals."""

    def __init__(self) -> None:
        self.local_names: set[str] = set()
        self.writes: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()
        self.imports: dict[str, list[tuple[int, tuple[str, str] | None, bool]]] = {}
        self.conditional = False

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.local_names.add(node.id)
            self.writes.add(node.id)

    def visit_arg(self, node: ast.arg) -> None:
        self.local_names.add(node.arg)
        self.writes.add(node.arg)

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name is not None:
            self.local_names.add(node.name)
            self.writes.add(node.name)
        if node.type is not None:
            self.visit(node.type)
        self._visit_conditional_statements(node.body)

    def _visit_conditional_statements(self, statements: list[ast.stmt]) -> None:
        previous = self.conditional
        self.conditional = True
        for statement in statements:
            self.visit(statement)
        self.conditional = previous

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.local_names.add(local)
            binding = ("module", "subprocess") if alias.name == "subprocess" else None
            self.imports.setdefault(local, []).append((node.lineno, binding, self.conditional))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            local = alias.asname or alias.name
            self.local_names.add(local)
            binding = (
                ("function", alias.name)
                if node.module == "subprocess" and alias.name in _SUBPROCESS_CALLS
                else None
            )
            self.imports.setdefault(local, []).append((node.lineno, binding, self.conditional))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_scope(node)

    def _visit_function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.local_names.add(node.name)
        self.writes.add(node.name)
        for expression in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
            if expression is not None:
                self.visit(expression)
        if node.returns is not None:
            self.visit(node.returns)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Defaults are evaluated here; parameters and body belong to the lambda.
        for expression in (*node.args.defaults, *node.args.kw_defaults):
            if expression is not None:
                self.visit(expression)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.local_names.add(node.name)
        self.writes.add(node.name)
        for expression in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(expression)

    def _visit_conditional(self, node: ast.AST) -> None:
        previous = self.conditional
        self.conditional = True
        self.generic_visit(node)
        self.conditional = previous

    visit_If = _visit_conditional
    visit_For = _visit_conditional
    visit_AsyncFor = _visit_conditional
    visit_While = _visit_conditional
    visit_Try = _visit_conditional
    visit_TryStar = _visit_conditional
    visit_With = _visit_conditional
    visit_AsyncWith = _visit_conditional

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        previous = self.conditional
        self.conditional = True
        for case in node.cases:
            self.visit(case)
        self.conditional = previous

    def visit_match_case(self, node: ast.match_case) -> None:
        self.visit(node.pattern)
        if node.guard is not None:
            self.visit(node.guard)
        for statement in node.body:
            self.visit(statement)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name is not None:
            self.local_names.add(node.name)
            self.writes.add(node.name)
        if node.pattern is not None:
            self.visit(node.pattern)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name is not None:
            self.local_names.add(node.name)
            self.writes.add(node.name)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        # Comprehension targets belong to their implicit scope, not this one.
        self.visit(node.iter)
        for condition in node.ifs:
            self.visit(condition)

    def scope(self, kind: str, parent: _PythonScope | None) -> _PythonScope:
        return _PythonScope(
            kind,
            parent,
            self.local_names - self.globals - self.nonlocals,
            self.writes - self.globals - self.nonlocals,
            self.globals,
            self.nonlocals,
            self.imports,
        )


def _scope_for(
    kind: str,
    parent: _PythonScope | None,
    body: list[ast.stmt],
    arguments: ast.arguments | None = None,
) -> _PythonScope:
    collector = _ScopeBindings()
    if arguments is not None:
        collector.visit(arguments)
    for statement in body:
        collector.visit(statement)
    return collector.scope(kind, parent)


def _lexical_parent(scope: _PythonScope | None) -> _PythonScope | None:
    """Class namespaces are not closure scopes for nested bodies."""
    while scope is not None and scope.kind == "class":
        scope = scope.parent
    return scope


def _scope_import(scope: _PythonScope, name: str, line: int) -> tuple[str, str] | None:
    """Resolve an imported client only when it is active and unambiguous."""
    current: _PythonScope | None = scope
    while current is not None:
        if name in current.globals:
            current = current.parent
            while current is not None and current.kind != "module":
                current = current.parent
            continue
        if name in current.nonlocals:
            return None
        if name in current.local_names:
            if name in current.writes:
                return None
            candidates = current.imports.get(name, [])
            active = [item for item in candidates if item[0] <= line]
            if not active or any(conditional for _, _, conditional in active):
                return None
            return active[-1][1]
        current = current.parent
    return None


class _SubprocessObserver(ast.NodeVisitor):
    def __init__(self, path: Path, module: ast.Module) -> None:
        self.path = path
        self.module = module
        self.scope = _scope_for("module", None, module.body)
        self.observations: list[DeploymentObservation] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for expression in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
            if expression is not None:
                self.visit(expression)
        if node.returns is not None:
            self.visit(node.returns)
        parent = _lexical_parent(self.scope)
        previous = self.scope
        self.scope = _scope_for("function", parent, node.body, node.args)
        for statement in node.body:
            self.visit(statement)
        self.scope = previous

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(expression)
        previous = self.scope
        self.scope = _scope_for("class", _lexical_parent(previous), node.body)
        for statement in node.body:
            self.visit(statement)
        self.scope = previous

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for expression in (*node.args.defaults, *node.args.kw_defaults):
            if expression is not None:
                self.visit(expression)
        previous = self.scope
        collector = _ScopeBindings()
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            collector.visit(argument)
        if node.args.vararg is not None:
            collector.visit(node.args.vararg)
        if node.args.kwarg is not None:
            collector.visit(node.args.kwarg)
        collector.visit(node.body)
        parent = _lexical_parent(previous)
        self.scope = collector.scope("function", parent)
        self.visit(node.body)
        self.scope = previous

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        expressions: tuple[ast.AST, ...],
    ) -> None:
        if generators:
            self.visit(generators[0].iter)
        collector = _ScopeBindings()
        for generator in generators:
            collector.visit(generator.target)
        previous = self.scope
        self.scope = collector.scope("comprehension", _lexical_parent(previous))
        for index, generator in enumerate(generators):
            if index:
                self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        for expression in expressions:
            self.visit(expression)
        self.scope = previous

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, (node.key, node.value))

    def visit_Call(self, node: ast.Call) -> None:
        call_name: str | None = None
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            binding = _scope_import(self.scope, node.func.value.id, node.lineno)
            if binding == ("module", "subprocess") and node.func.attr in _SUBPROCESS_CALLS:
                call_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            binding = _scope_import(self.scope, node.func.id, node.lineno)
            if binding is not None and binding[0] == "function":
                call_name = binding[1]
        if call_name is not None:
            shell = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "shell"),
                ast.Constant(value=False),
            )
            argv = _literal_argv(node.args[0]) if node.args else None
            if isinstance(shell, ast.Constant) and shell.value is False and argv is not None:
                self.observations.append(
                    DeploymentObservation(
                        self.path, node.lineno, "subprocess_argv", call_name, argv, "exact"
                    )
                )
            else:
                reason = (
                    "shell execution is excluded"
                    if isinstance(shell, ast.Constant) and shell.value is True
                    else "dynamic argv or shell mode"
                )
                self.observations.append(
                    DeploymentObservation(
                        self.path,
                        node.lineno,
                        "subprocess_argv",
                        call_name,
                        None,
                        "uncertain",
                        reason,
                    )
                )
        self.generic_visit(node)


def extract_subprocess_observations(
    source: str, source_path: Path | str = "<memory>"
) -> tuple[DeploymentObservation, ...]:
    """Observe canonical subprocess imports without leaking bindings across scopes."""
    path = Path(source_path)
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return ()
    observer = _SubprocessObserver(path, tree)
    observer.visit(tree)
    return tuple(
        sorted(observer.observations, key=lambda item: (item.line, item.kind, item.key or ""))
    )
