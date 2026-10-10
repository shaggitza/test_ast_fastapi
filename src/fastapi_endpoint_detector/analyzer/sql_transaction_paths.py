"""Bounded source-backed SQL stage-to-boundary ordering diagnostics."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from fastapi_endpoint_detector.models.effect_contract import load_effect_contracts
from fastapi_endpoint_detector.models.sql_transaction import (
    SQLTransactionContextPath,
    SQLTransactionOrderedPath,
    SQLTransactionPathDiagnostic,
    SQLTransactionPathError,
    SQLTransactionPathReport,
    SQLTransactionSourceProjection,
    build_sql_transaction_context_path,
    build_sql_transaction_ordered_path,
    build_sql_transaction_path_report,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from fastapi_endpoint_detector.models.effect_contract_audit import (
        EffectContractAudit,
        EffectContractAuditOccurrence,
    )
    from fastapi_endpoint_detector.models.sql_transaction import (
        SQLTransactionBeginScopeEvidence,
        SQLTransactionReport,
    )

_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_BOUNDARY = Literal["flush", "commit", "rollback"]
_REASON = Literal[
    "different_source_scope",
    "source_call_unavailable",
    "receiver_unavailable",
    "receiver_mismatch",
    "receiver_reassigned",
    "control_flow_unavailable",
    "boundary_precedes_stage",
]


@dataclass(frozen=True)
class _SourceCall:
    """Exact callee span plus conservative lexical context."""

    file_path: str
    function_name: str | None
    statement_index: int | None
    receiver_key: tuple[str, ...] | None
    receiver_hash: str | None
    function_body: tuple[ast.stmt, ...] | None
    context_id: str | None
    context_body_index: int | None


class _CallIndexer(ast.NodeVisitor):
    """Index call callee spans without treating nested control flow as straight-line."""

    def __init__(
        self,
        file_path: str,
        *,
        captured_context_receivers: frozenset[tuple[int, int, int, int]] = frozenset(),
    ) -> None:
        self.file_path = file_path
        self.captured_context_receivers = captured_context_receivers
        self.qualname: list[str] = []
        self.calls: dict[tuple[int, int, int, int], _SourceCall] = {}
        self._indexed_context_nodes: set[int] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.qualname.append(node.name)
        self.generic_visit(node)
        self.qualname.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self.qualname:
            self._record(node, ".".join(self.qualname), None, None, overwrite=False)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self._visit_nested_context(node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_nested_context(node)
        self.generic_visit(node)

    def _visit_nested_context(self, node: ast.With | ast.AsyncWith) -> None:
        if self.qualname and id(node) not in self._indexed_context_nodes:
            self._record_context(node, ".".join(self.qualname), None, ())

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.qualname.append(node.name)
        function_name = ".".join(self.qualname)
        body = tuple(node.body)
        for index, statement in enumerate(body):
            direct = _direct_statement_call(statement)
            if direct is not None:
                self._record(direct, function_name, index, body)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                self._record_context(statement, function_name, index, body)
        # Generic traversal records control-flow calls as non-straight-line and
        # gives nested definitions their own lexical identity.
        for statement in node.body:
            self.visit(statement)
        self.qualname.pop()

    def _record(
        self,
        call: ast.Call,
        function_name: str,
        statement_index: int | None,
        function_body: tuple[ast.stmt, ...] | None,
        *,
        context_id: str | None = None,
        context_body_index: int | None = None,
        receiver_key_override: tuple[str, ...] | None = None,
        overwrite: bool = True,
    ) -> None:
        function = call.func
        if function.end_lineno is None or function.end_col_offset is None:
            return
        key = (
            function.lineno,
            function.col_offset,
            function.end_lineno,
            function.end_col_offset,
        )
        receiver_key = receiver_key_override or (
            _receiver_key(function.value) if isinstance(function, ast.Attribute) else None
        )
        record = _SourceCall(
            file_path=self.file_path,
            function_name=function_name,
            statement_index=statement_index,
            receiver_key=receiver_key,
            receiver_hash=(
                _semantic_hash({"kind": "receiver_expression", "parts": receiver_key})
                if receiver_key is not None
                else None
            ),
            function_body=function_body,
            context_id=context_id,
            context_body_index=context_body_index,
        )
        if overwrite or key not in self.calls:
            self.calls[key] = record

    def _record_context(  # noqa: PLR0911
        self,
        statement: ast.With | ast.AsyncWith,
        function_name: str,
        statement_index: int | None,
        function_body: tuple[ast.stmt, ...] | None,
    ) -> None:
        self._indexed_context_nodes.add(id(statement))
        if len(statement.items) != 1:
            return
        item = statement.items[0]
        begin = _unwrap_call(item.context_expr)
        if begin is None:
            return
        if item.optional_vars is not None and _target_key(item.optional_vars) is None:
            return
        begin_receiver = (
            _receiver_key(begin.func.value) if isinstance(begin.func, ast.Attribute) else None
        )
        function = begin.func
        if function.end_lineno is None or function.end_col_offset is None:
            return
        begin_key = (
            function.lineno,
            function.col_offset,
            function.end_lineno,
            function.end_col_offset,
        )
        captured_receiver = (
            _target_key(item.optional_vars) if item.optional_vars is not None else None
        )
        receiver_is_shadowed = (
            begin_receiver is not None
            and captured_receiver is not None
            and len(captured_receiver) <= len(begin_receiver)
            and begin_receiver[: len(captured_receiver)] == captured_receiver
        )
        receiver_yield_is_authorized = begin_key in self.captured_context_receivers
        if receiver_yield_is_authorized and captured_receiver is not None:
            # The exact contract says stages use the value yielded by this
            # context manager. Prefer that receiver even when the factory
            # expression itself has a receiver (for example factory.begin()).
            begin_receiver = captured_receiver
        elif receiver_is_shadowed:
            return
        # `as name` captures __enter__/__aenter__'s yielded value. It can stand
        # in for the receiver only when the exact begin contract explicitly
        # declares that the context yields the receiver used by its scoped stage.
        if begin_receiver is None:
            if not receiver_yield_is_authorized or item.optional_vars is None:
                return
            begin_receiver = captured_receiver
            if begin_receiver is None:
                return
        context_id = _semantic_hash(
            {
                "kind": "sql_context",
                "file": self.file_path,
                "function": function_name,
                "line": statement.lineno,
                "column": statement.col_offset,
            }
        )
        self._record(
            begin,
            function_name,
            statement_index,
            function_body,
            context_id=context_id,
            receiver_key_override=begin_receiver,
        )
        context_body = tuple(statement.body)
        for body_index, body_statement in enumerate(context_body):
            direct = _direct_statement_call(body_statement)
            if direct is not None:
                self._record(
                    direct,
                    function_name,
                    body_index,
                    context_body,
                    context_id=context_id,
                    context_body_index=body_index,
                )


def _semantic_hash(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _unwrap_call(value: ast.expr | None) -> ast.Call | None:
    if isinstance(value, ast.Await):
        value = value.value
    return value if isinstance(value, ast.Call) else None


def _direct_statement_call(statement: ast.stmt) -> ast.Call | None:
    """Accept only unconditional top-level expression/assignment calls."""
    value: ast.expr | None = None
    if isinstance(statement, (ast.Expr, ast.Assign, ast.AnnAssign)):
        value = statement.value
    return _unwrap_call(value)


def _receiver_key(expression: ast.expr) -> tuple[str, ...] | None:
    """Return a finite syntactic Name/Attribute receiver, never calls/subscripts."""
    parts: list[str] = []
    current = expression
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return tuple(reversed(parts))


def _target_key(target: ast.expr) -> tuple[str, ...] | None:
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, ast.Attribute):
        return _receiver_key(target)
    return None


class _AssignmentFinder(ast.NodeVisitor):
    """Find reassignment of a receiver or any of its lexical ancestors."""

    def __init__(self, receiver_key: tuple[str, ...]) -> None:
        self.receiver_key = receiver_key
        self.found = False

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # A local annotation without a value does not assign to its target.
        if node.value is not None:
            self.visit(node.target)
            self.visit(node.value)
        elif isinstance(node.target, ast.Attribute):
            self.visit(node.target.value)
        elif isinstance(node.target, ast.Subscript):
            self.visit(node.target.value)
            self.visit(node.target.slice)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._check((node.id,))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            key = _target_key(node)
            if key is not None:
                self._check(key)
        self.generic_visit(node)

    def _check(self, target: tuple[str, ...]) -> None:
        shorter = min(len(target), len(self.receiver_key))
        if target[:shorter] == self.receiver_key[:shorter]:
            self.found = True


def _control_flow_between(
    body: tuple[ast.stmt, ...],
    start_index: int,
    end_index: int,
) -> bool:
    control_statements = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.Return,
        ast.Raise,
        ast.Break,
        ast.Continue,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
    )
    try_star = getattr(ast, "TryStar", ast.Try)
    return any(
        isinstance(statement, (*control_statements, try_star))
        for statement in body[start_index + 1 : end_index]
    )


def _receiver_reassigned(
    body: tuple[ast.stmt, ...],
    start_index: int,
    end_index: int,
    receiver_key: tuple[str, ...],
) -> bool:
    finder = _AssignmentFinder(receiver_key)
    for statement in body[start_index + 1 : end_index]:
        finder.visit(statement)
        if finder.found:
            return True
    return False


def _safe_source_path(root: Path, relative_path: str) -> Path | None:
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _load_call_index(
    root: Path,
    file_path: str,
    *,
    captured_context_receivers: frozenset[tuple[int, int, int, int]] = frozenset(),
) -> dict[tuple[int, int, int, int], _SourceCall]:
    source = _safe_source_path(root, file_path)
    if source is None:
        return {}
    try:
        raw = source.read_bytes()
    except OSError:
        return {}
    if len(raw) > _MAX_SOURCE_BYTES:
        return {}
    try:
        tree = ast.parse(raw, filename=str(source))
    except (SyntaxError, ValueError):
        return {}
    indexer = _CallIndexer(
        file_path,
        captured_context_receivers=captured_context_receivers,
    )
    indexer.visit(tree)
    return indexer.calls


def _occurrence_key(occurrence: EffectContractAuditOccurrence) -> tuple[int, int, int, int] | None:
    if occurrence.end_line is None or occurrence.end_column is None:
        return None
    return (
        occurrence.line,
        occurrence.column,
        occurrence.end_line,
        occurrence.end_column,
    )


def _diagnostic(
    endpoint_id: str,
    stage_id: str,
    boundary_id: str,
    reason: _REASON,
) -> SQLTransactionPathDiagnostic:
    return SQLTransactionPathDiagnostic(
        endpoint_id=endpoint_id,
        stage_occurrence_id=stage_id,
        boundary_occurrence_id=boundary_id,
        reason_code=reason,
    )


def _module_snapshot(root: Path, module: str) -> tuple[str, bytes] | None:
    relative = Path("source", *module.split(".")).with_suffix(".py.txt")
    path = _safe_source_path(root, relative.as_posix())
    if path is None:
        return None
    try:
        return relative.as_posix(), path.read_bytes()
    except OSError:
        return None


def _attribute_on_name(call: ast.Call, attribute: str, name: str) -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == attribute
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == name
        and isinstance(call.func.value.ctx, ast.Load)
    )


def _owned_nodes(node: ast.AST) -> Iterable[ast.AST]:
    """Walk one executable scope, excluding deferred nested scopes."""
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            yield child
            continue
        yield from _owned_nodes(child)


def _scope_parents(root: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map parents within one scope, leaving deferred nested bodies disconnected."""
    parents: dict[ast.AST, ast.AST] = {}

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            parents[child] = node
            if not isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                visit(child)

    visit(root)
    return parents


def _has_ambiguous_scope_binding(  # noqa: PLR0911
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
    *,
    allowed_import: ast.ImportFrom | None = None,
) -> bool:
    """Reject names that Python may bind locally anywhere in this function."""
    arguments = function.args
    if any(
        argument.arg == name
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *([arguments.vararg] if arguments.vararg else []),
            *([arguments.kwarg] if arguments.kwarg else []),
        )
    ):
        return True
    for node in _owned_nodes(function):
        if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            return True
        if isinstance(node, ast.ExceptHandler) and node.name == name:
            return True
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == name:
            return True
        if isinstance(node, ast.MatchMapping) and node.rest == name:
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if node is allowed_import:
                continue
            for alias in node.names:
                bound = alias.asname or (
                    alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name
                )
                if bound == name:
                    return True
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node is not function
            and node.name == name
        ):
            return True
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id == name
        ):
            return True
    return False


def _module_binding_is_ambiguous(
    module: ast.Module,
    name: str,
    allowed_import: ast.ImportFrom,
) -> bool:
    """Require one module binding: the import that supplied the wrapper."""
    bindings: list[tuple[ast.AST, str]] = []

    def visit(node: ast.AST) -> None:
        # Function and class bodies have their own namespaces. Their names bind
        # in the containing scope, while decorators/defaults/bases execute here.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bindings.append((node, node.name))
            for expression in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
                if expression is not None:
                    visit(expression)
            return
        if isinstance(node, ast.ClassDef):
            bindings.append((node, node.name))
            for class_expression in (*node.decorator_list, *node.bases, *node.keywords):
                visit(class_expression)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound = alias.asname or (
                    alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name
                )
                bindings.append((node, bound))
            return
        if isinstance(node, ast.ExceptHandler) and node.name:
            bindings.append((node, node.name))
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bindings.append((node, node.id))
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bindings.append((node, node.name))
        if isinstance(node, ast.MatchMapping) and node.rest:
            bindings.append((node, node.rest))
        for nested in ast.iter_child_nodes(node):
            visit(nested)

    for statement in module.body:
        visit(statement)
    matching = [(node, bound) for node, bound in bindings if bound == name]
    return len(matching) != 1 or matching[0][0] is not allowed_import


def _has_dynamic_module_binding_mutation(module: ast.Module) -> bool:  # noqa: PLR0911, PLR0912, PLR0915
    """Reject module-executed operations that can replace a binding indirectly.

    Static binding counts cannot account for writes through the module globals
    mapping, or code evaluated in that namespace. Keep the policy deliberately
    conservative and inspect only code executed while the module is initialized.
    """

    postponed_annotations = any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "__future__"
        and any(alias.name == "annotations" for alias in statement.names)
        for statement in module.body
    )

    def executed_nodes(node: ast.AST) -> Iterable[ast.AST]:  # noqa: PLR0912
        """Walk expressions evaluated during module initialization.

        Function bodies and lambda bodies are deferred, but their decorators,
        defaults and annotations (when eagerly evaluated) are not. Class bodies
        execute immediately and can access the module globals mapping.
        """
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                expressions: list[ast.AST] = [
                    *child.decorator_list,
                    *child.args.defaults,
                    *(item for item in child.args.kw_defaults if item is not None),
                ]
                if not postponed_annotations:
                    arguments = child.args.args + child.args.kwonlyargs + child.args.posonlyargs
                    expressions.extend(
                        argument.annotation
                        for argument in arguments
                        if argument.annotation is not None
                    )
                    if child.args.vararg and child.args.vararg.annotation:
                        expressions.append(child.args.vararg.annotation)
                    if child.args.kwarg and child.args.kwarg.annotation:
                        expressions.append(child.args.kwarg.annotation)
                    if child.returns:
                        expressions.append(child.returns)
                for expression in expressions:
                    yield expression
                    yield from executed_nodes(expression)
                continue
            if isinstance(child, ast.Lambda):
                for default_expr in (*child.args.defaults, *child.args.kw_defaults):
                    if default_expr is not None:
                        yield default_expr
                        yield from executed_nodes(default_expr)
                continue
            if isinstance(child, ast.ClassDef):
                for class_expression in (*child.decorator_list, *child.bases, *child.keywords):
                    yield class_expression
                    yield from executed_nodes(class_expression)
                for statement in child.body:
                    yield statement
                    yield from executed_nodes(statement)
                continue
            yield child
            yield from executed_nodes(child)

    # Track simple module aliases of dynamic evaluators (for example
    # ``rebind = exec`` and ``from builtins import exec as run``).
    dynamic_aliases = {"exec", "eval"}
    for statement in executed_nodes(module):
        if isinstance(statement, ast.ImportFrom) and statement.module == "builtins":
            dynamic_aliases.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name in {"exec", "eval"}
            )
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = statement.value
            if isinstance(value, ast.Name) and value.id in dynamic_aliases:
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                dynamic_aliases.update(
                    target.id
                    for item in targets
                    for target in ast.walk(item)
                    if isinstance(target, ast.Name)
                )

    for node in executed_nodes(module):
        if any(
            isinstance(child, ast.Attribute) and child.attr == "__dict__"
            for child in ast.walk(node)
        ):
            return True
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and any(
                isinstance(child, ast.Attribute) and child.attr == "__dict__"
                for child in ast.walk(node.value)
            )
        ):
            return True
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in dynamic_aliases:
            return True
        if isinstance(func, ast.Attribute) and func.attr in {"exec", "eval"}:
            return True
        if isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2:
            if isinstance(node.args[1], ast.Constant) and node.args[1].value in {"exec", "eval"}:
                return True
            if isinstance(node.args[0], ast.Name) and node.args[0].id == "__builtins__":
                return True
        if (
            isinstance(func, ast.Subscript)
            and isinstance(func.value, ast.Name)
            and func.value.id == "__builtins__"
        ):
            return True
        # Any access to globals() during module initialization can expose the
        # namespace to mutation, including aliases and update/setitem forms.
        if any(
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id in {"globals", "locals"}
            for child in ast.walk(node)
        ):
            return True
        if isinstance(func, ast.Name) and func.id == "vars" and not node.args:
            return True
        if isinstance(func, ast.Attribute) and func.attr in {"setattr", "update"}:
            if any(
                isinstance(child, ast.Attribute) and child.attr == "__dict__"
                for child in ast.walk(func.value)
            ):
                return True
            if isinstance(func.value, ast.Name) and func.value.id == "setattr":
                return True
        if isinstance(func, ast.Name) and func.id == "setattr":
            return True
    return False


def _enclosing_receiver_context(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    receiver: tuple[str, ...] | None,
) -> ast.With | ast.AsyncWith | None:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.With, ast.AsyncWith)) and any(
            _target_key(item.optional_vars) == receiver
            for item in current.items
            if item.optional_vars is not None
        ):
            return current
        current = parents.get(current)
    return None


def _fixture_source_projections(  # noqa: PLR0912, PLR0915
    root: Path,
    audit: EffectContractAudit,
) -> list[SQLTransactionSourceProjection]:
    """Associate an unresolved SQL method with an exact yielded wrapper receiver.

    This is deliberately a source projection, not a resolved SQL stage: the
    method remains unresolved and the record cannot establish persistence.
    """
    result: list[SQLTransactionSourceProjection] = []
    fixture_effects = root / "effects.yaml"
    try:
        loaded_contracts = load_effect_contracts(fixture_effects)
    except (OSError, ValueError):
        return result
    contract_by_id = {item.id: item for item in loaded_contracts.document.contracts}
    for begin in audit.occurrences:
        contract = contract_by_id.get(begin.contract_id or "")
        if (
            contract is None
            or loaded_contracts.contract_hashes.get(contract.id) != begin.contract_hash
            or contract.behavior.stage_receiver_from_yield is not True
            or contract.behavior.context_exit is None
            or not begin.canonical_symbol
        ):
            continue
        wrapper_module = begin.canonical_symbol.rsplit(".", 1)[0]
        wrapper = _module_snapshot(root, wrapper_module)
        endpoint_candidates = [
            item
            for item in audit.occurrences
            if item.resolver_status.value != "exact"
            and item.reason_code == "fixture_type_proof_unavailable"
            and any(
                endpoint.id == begin_endpoint.id
                for endpoint in item.endpoints
                for begin_endpoint in begin.endpoints
            )
            and item.file_path == begin.file_path
            and item.source_spelling.endswith(".execute")
        ]
        if wrapper is None or len(endpoint_candidates) != 1:
            continue
        stage = endpoint_candidates[0]
        endpoint_id = next(
            (
                endpoint.id
                for endpoint in begin.endpoints
                if any(candidate.id == endpoint.id for candidate in stage.endpoints)
            ),
            None,
        )
        if endpoint_id is None:
            continue
        endpoint_path = _safe_source_path(root, stage.file_path)
        if endpoint_path is None:
            continue
        try:
            endpoint_bytes = endpoint_path.read_bytes()
            wrapper_tree = ast.parse(wrapper[1], filename=wrapper[0])
            endpoint_tree = ast.parse(endpoint_bytes, filename=stage.file_path)
        except (OSError, SyntaxError, ValueError):
            continue
        wrapper_fn = next(
            (
                node
                for node in wrapper_tree.body
                if isinstance(node, ast.AsyncFunctionDef)
                and node.name == begin.canonical_symbol.rsplit(".", 1)[-1]
            ),
            None,
        )
        if wrapper_fn is None:
            continue
        delegated_module = None
        wrapper_yields_receiver = False
        wrapper_scope_calls: dict[str, str] = {}
        wrapper_import_nodes: dict[str, ast.ImportFrom] = {}
        for node in _owned_nodes(wrapper_fn):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    wrapper_scope_calls[local_name] = f"{node.module}.{alias.name}"
                    wrapper_import_nodes[local_name] = node
            if isinstance(node, ast.AsyncWith):
                for item in node.items:
                    captured = _target_key(item.optional_vars) if item.optional_vars else None
                    target = item.context_expr
                    if (
                        captured is not None
                        and isinstance(target, ast.Call)
                        and isinstance(target.func, ast.Name)
                    ):
                        canonical = wrapper_scope_calls.get(target.func.id)
                        if canonical is None:
                            continue
                        import_node = wrapper_import_nodes.get(target.func.id)
                        if import_node is None or _has_ambiguous_scope_binding(
                            wrapper_fn, target.func.id, allowed_import=import_node
                        ):
                            continue
                        delegated_module = canonical.rsplit(".", 1)[0]
                        target = item.context_expr
                        wrapper_yields_receiver = any(
                            isinstance(child, ast.Expr)
                            and isinstance(child.value, ast.Yield)
                            and child.value.value is not None
                            and _target_key(child.value.value) == captured
                            for child in node.body
                        )
        if not delegated_module or not wrapper_yields_receiver:
            continue
        delegated = _module_snapshot(root, delegated_module)
        if delegated is None:
            continue
        try:
            delegated_tree = ast.parse(delegated[1], filename=delegated[0])
        except SyntaxError:
            continue
        delegate_name = begin.canonical_symbol.rsplit(".", 1)[-1]
        delegate_fn = next(
            (
                node
                for node in delegated_tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == delegate_name
            ),
            None,
        )
        if delegate_fn is None:
            continue
        delegate_parents = _scope_parents(delegate_fn)
        yielded_contexts = tuple(
            (
                node,
                _receiver_key(node.value),
                _enclosing_receiver_context(node, delegate_parents, _receiver_key(node.value)),
            )
            for node in _owned_nodes(delegate_fn)
            if isinstance(node, ast.Yield) and node.value is not None
        )
        yielded = {receiver for _node, receiver, context in yielded_contexts if context is not None}
        context_nodes = {
            context for _node, _receiver, context in yielded_contexts if context is not None
        }
        boundary_calls = tuple(
            node
            for node in _owned_nodes(delegate_fn)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        )

        def has_boundary(
            name: str,
            calls: tuple[ast.Call, ...] = boundary_calls,
            yielded_receivers: set[tuple[str, ...] | None] = yielded,
            expected_contexts: set[ast.With | ast.AsyncWith] = context_nodes,
            parents: dict[ast.AST, ast.AST] = delegate_parents,
        ) -> bool:
            return any(
                node.func.attr == name
                and _receiver_key(node.func.value) in yielded_receivers
                and node.args == []
                and _enclosing_receiver_context(node, parents, _receiver_key(node.func.value))
                in expected_contexts
                for node in calls
                if isinstance(node.func, ast.Attribute)
            )

        yield_session = (
            len(yielded) == 1
            and None not in yielded
            and len(context_nodes) == 1
            and len(yielded_contexts) == 1
        )
        has_commit = has_boundary("commit")
        has_rollback = has_boundary("rollback")
        if not (yield_session and has_commit and has_rollback):
            continue
        handler = next(
            (
                node
                for node in endpoint_tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any(
                    isinstance(child, ast.Call)
                    and child.func.lineno == stage.line
                    and child.func.col_offset == stage.column
                    for child in _owned_nodes(node)
                )
            ),
            None,
        )
        if handler is None:
            continue
        imported_wrapper_bindings = [
            (node, alias.asname or alias.name)
            for node in endpoint_tree.body
            if isinstance(node, ast.ImportFrom) and node.module == wrapper_module
            for alias in node.names
            if f"{node.module}.{alias.name}" == begin.canonical_symbol
        ]
        if len(imported_wrapper_bindings) != 1:
            continue
        wrapper_import, imported_wrapper_name = imported_wrapper_bindings[0]
        if _module_binding_is_ambiguous(endpoint_tree, imported_wrapper_name, wrapper_import):
            continue
        if _has_dynamic_module_binding_mutation(endpoint_tree):
            continue
        if _has_ambiguous_scope_binding(handler, imported_wrapper_name):
            continue
        match = None
        for node in _owned_nodes(handler):
            if not isinstance(node, ast.AsyncWith) or len(node.items) != 1:
                continue
            item = node.items[0]
            context_call = item.context_expr
            if (
                not isinstance(context_call, ast.Call)
                or not isinstance(context_call.func, ast.Name)
                or context_call.func.id != imported_wrapper_name
            ):
                continue
            if (
                context_call.func.lineno,
                context_call.func.col_offset,
                context_call.func.end_lineno,
                context_call.func.end_col_offset,
            ) != (begin.line, begin.column, begin.end_line, begin.end_column):
                continue
            captured = _target_key(item.optional_vars) if item.optional_vars is not None else None
            if captured is None or len(captured) != 1:
                continue
            receiver_name = captured[0]
            stage_node = next(
                (
                    child
                    for child in _owned_nodes(node)
                    if isinstance(child, ast.Call)
                    and _attribute_on_name(child, "execute", receiver_name)
                    and child.func.lineno == stage.line
                    and child.func.col_offset == stage.column
                ),
                None,
            )
            if stage_node is None or not any(
                isinstance(child, ast.Await) and child.value is stage_node
                for child in _owned_nodes(node)
            ):
                continue
            # The stage must be a direct expression in the owned context body.
            if not any(
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Await)
                and stmt.value.value is stage_node
                for stmt in node.body
            ):
                continue
            if (
                len(
                    [
                        child
                        for child in _owned_nodes(handler)
                        if isinstance(child, ast.Call)
                        and _attribute_on_name(child, "execute", receiver_name)
                    ]
                )
                != 1
            ):
                continue
            match = node
            break
        if match is None:
            continue
        captured_target = match.items[0].optional_vars
        if captured_target is None:
            continue
        receiver = ast.unparse(captured_target)
        receiver_key = _target_key(captured_target)
        if receiver_key is None or _receiver_reassigned(
            tuple(match.body), -1, len(match.body), receiver_key
        ):
            continue
        receiver_hash = _semantic_hash({"kind": "receiver_expression", "parts": receiver_key})
        endpoint_hash = f"sha256:{hashlib.sha256(endpoint_bytes).hexdigest()}"
        wrapper_hash = f"sha256:{hashlib.sha256(wrapper[1]).hexdigest()}"
        delegated_hash = f"sha256:{hashlib.sha256(delegated[1]).hexdigest()}"
        uncertainty = (
            "SQL method identity is unresolved because fixture type proof is unavailable.",
            "Projection depends on the exact matched context contract and captured yield receiver.",
            "Normal or exceptional exit is conditional; runtime outcome and persistence are not "
            "established.",
        )
        provisional = SQLTransactionSourceProjection.model_construct(
            id="sha256:" + "0" * 64,
            endpoint_id=endpoint_id,
            begin_occurrence_id=begin.id,
            unresolved_stage_occurrence_id=stage.id,
            endpoint_file_path=stage.file_path,
            endpoint_source_hash=endpoint_hash,
            wrapper_file_path=wrapper[0],
            wrapper_source_hash=wrapper_hash,
            delegated_wrapper_file_path=delegated[0],
            delegated_wrapper_source_hash=delegated_hash,
            function_name=handler.name,
            receiver_hash=receiver_hash,
            receiver_expression=receiver,
            uncertainty=uncertainty,
        )
        result.append(
            SQLTransactionSourceProjection.model_validate(
                {
                    **provisional.model_dump(mode="python"),
                    "id": _semantic_hash(provisional.identity_payload()),
                }
            )
        )
    return result


def _nearest_begin(
    begin_occurrences: Iterable[EffectContractAuditOccurrence],
    contexts: dict[str, _SourceCall | None],
    stage: _SourceCall,
) -> str | None:
    eligible: list[tuple[int, str]] = []
    assert stage.statement_index is not None
    assert stage.function_body is not None
    assert stage.receiver_key is not None
    for occurrence in begin_occurrences:
        context = contexts.get(occurrence.id)
        if (
            context is None
            or context.file_path != stage.file_path
            or context.function_name != stage.function_name
            or context.statement_index is None
            or context.receiver_key != stage.receiver_key
            or context.statement_index >= stage.statement_index
            or context.function_body is not stage.function_body
            or _receiver_reassigned(
                stage.function_body,
                context.statement_index,
                stage.statement_index,
                stage.receiver_key,
            )
        ):
            continue
        eligible.append((context.statement_index, occurrence.id))
    return max(eligible)[1] if eligible else None


def _context_manager_paths(
    endpoint_id: str,
    begin_scopes: tuple[SQLTransactionBeginScopeEvidence, ...],
    stage_ids: tuple[str, ...],
    contexts: dict[str, _SourceCall | None],
) -> list[SQLTransactionContextPath]:
    paths: list[SQLTransactionContextPath] = []
    for begin_scope in begin_scopes:
        if begin_scope.context_exit is None:
            continue
        begin = contexts.get(begin_scope.occurrence_id)
        if begin is None or begin.context_id is None or begin.receiver_key is None:
            continue
        for stage_id in stage_ids:
            stage = contexts.get(stage_id)
            if (
                stage is None
                or stage.context_id != begin.context_id
                or stage.context_body_index is None
                or stage.file_path != begin.file_path
                or stage.function_name is None
                or stage.function_name != begin.function_name
                or stage.receiver_key is None
                or stage.receiver_key != begin.receiver_key
                or stage.receiver_hash is None
                or stage.function_body is None
                or _receiver_reassigned(
                    stage.function_body,
                    -1,
                    stage.context_body_index,
                    stage.receiver_key,
                )
            ):
                continue
            paths.append(
                build_sql_transaction_context_path(
                    endpoint_id=endpoint_id,
                    file_path=stage.file_path,
                    function_name=stage.function_name,
                    receiver_hash=stage.receiver_hash,
                    begin_occurrence_id=begin_scope.occurrence_id,
                    begin_scope=begin_scope.scope,
                    context_exit=begin_scope.context_exit,
                    stage_occurrence_id=stage_id,
                    limitations=(
                        "Normal exit makes commit or savepoint release reachable; exceptional "
                        "exit makes rollback reachable. Which exit occurs is not established.",
                        "Context-manager evidence proves exact lexical containment and stable "
                        "receiver spelling, not runtime transaction identity or outcome success.",
                        "Persistence remains not established and candidates are never promoted.",
                    ),
                )
            )
    return paths


def build_sql_transaction_path_diagnostics(  # noqa: PLR0912, PLR0915
    source_root: Path,
    audit: EffectContractAudit,
    transaction_report: SQLTransactionReport,
    *,
    max_pairs: int,
) -> SQLTransactionPathReport:
    """Prove only bounded same-scope lexical ordering over one stable receiver spelling."""
    if not 1 <= max_pairs <= 10_000:
        raise SQLTransactionPathError("SQL transaction max_pairs must be between 1 and 10000")
    root = source_root.resolve()
    occurrence_by_id = {item.id: item for item in audit.occurrences}
    pair_count = sum(
        len(item.stage_occurrence_ids)
        * (
            len(item.begin_occurrence_ids)
            + len(item.flush_occurrence_ids)
            + len(item.commit_occurrence_ids)
            + len(item.rollback_occurrence_ids)
        )
        for item in transaction_report.endpoint_evidence
    )
    if pair_count > max_pairs:
        raise SQLTransactionPathError(
            f"SQL transaction path pair limit exceeded: {pair_count} > {max_pairs}"
        )

    files = {
        occurrence_by_id[occurrence_id].file_path
        for evidence in transaction_report.endpoint_evidence
        for occurrence_id in (
            *evidence.stage_occurrence_ids,
            *evidence.flush_occurrence_ids,
            *evidence.begin_occurrence_ids,
            *evidence.commit_occurrence_ids,
            *evidence.rollback_occurrence_ids,
        )
    }
    captured_context_receivers: dict[str, set[tuple[int, int, int, int]]] = {}
    for evidence in transaction_report.endpoint_evidence:
        for scope in evidence.begin_scopes:
            if not scope.stage_receiver_from_yield:
                continue
            occurrence = occurrence_by_id[scope.occurrence_id]
            key = _occurrence_key(occurrence)
            if key is not None:
                captured_context_receivers.setdefault(occurrence.file_path, set()).add(key)
    indexes = {
        file_path: _load_call_index(
            root,
            file_path,
            captured_context_receivers=frozenset(captured_context_receivers.get(file_path, ())),
        )
        for file_path in sorted(files)
    }
    contexts: dict[str, _SourceCall | None] = {}
    for occurrence_id, occurrence in occurrence_by_id.items():
        key = _occurrence_key(occurrence)
        contexts[occurrence_id] = indexes.get(occurrence.file_path, {}).get(key) if key else None

    paths: list[SQLTransactionOrderedPath] = []
    context_paths: list[SQLTransactionContextPath] = []
    diagnostics: list[SQLTransactionPathDiagnostic] = []
    common_limitations = (
        "Ordering proves only lexical source order in one direct function body; runtime "
        "execution, exceptions, aliases, and transaction identity are not established.",
        "Receiver equality is a stable finite source expression, not runtime object identity.",
    )
    for evidence in transaction_report.endpoint_evidence:
        context_paths.extend(
            _context_manager_paths(
                evidence.endpoint_id,
                evidence.begin_scopes,
                evidence.stage_occurrence_ids,
                contexts,
            )
        )
        begins = tuple(occurrence_by_id[item] for item in evidence.begin_occurrence_ids)
        begin_scope_by_id = {item.occurrence_id: item.scope for item in evidence.begin_scopes}
        boundaries: tuple[tuple[str, _BOUNDARY], ...] = (
            tuple((item, "flush") for item in evidence.flush_occurrence_ids)
            + tuple((item, "commit") for item in evidence.commit_occurrence_ids)
            + tuple((item, "rollback") for item in evidence.rollback_occurrence_ids)
        )
        for stage_id in evidence.stage_occurrence_ids:
            stage = contexts.get(stage_id)
            for boundary_id, boundary_kind in boundaries:
                boundary = contexts.get(boundary_id)
                if stage is None or boundary is None:
                    diagnostics.append(
                        _diagnostic(
                            evidence.endpoint_id,
                            stage_id,
                            boundary_id,
                            "source_call_unavailable",
                        )
                    )
                    continue
                if (
                    stage.file_path != boundary.file_path
                    or stage.function_name is None
                    or stage.function_name != boundary.function_name
                ):
                    diagnostics.append(
                        _diagnostic(
                            evidence.endpoint_id,
                            stage_id,
                            boundary_id,
                            "different_source_scope",
                        )
                    )
                    continue
                if (
                    stage.statement_index is None
                    or boundary.statement_index is None
                    or stage.function_body is None
                    or stage.function_body is not boundary.function_body
                ):
                    diagnostics.append(
                        _diagnostic(
                            evidence.endpoint_id,
                            stage_id,
                            boundary_id,
                            "control_flow_unavailable",
                        )
                    )
                    continue
                if stage.receiver_key is None or boundary.receiver_key is None:
                    diagnostics.append(
                        _diagnostic(
                            evidence.endpoint_id,
                            stage_id,
                            boundary_id,
                            "receiver_unavailable",
                        )
                    )
                    continue
                if stage.receiver_key != boundary.receiver_key:
                    diagnostics.append(
                        _diagnostic(
                            evidence.endpoint_id,
                            stage_id,
                            boundary_id,
                            "receiver_mismatch",
                        )
                    )
                    continue
                if boundary.statement_index <= stage.statement_index:
                    diagnostics.append(
                        _diagnostic(
                            evidence.endpoint_id,
                            stage_id,
                            boundary_id,
                            "boundary_precedes_stage",
                        )
                    )
                    continue
                if _control_flow_between(
                    stage.function_body,
                    stage.statement_index,
                    boundary.statement_index,
                ):
                    diagnostics.append(
                        _diagnostic(
                            evidence.endpoint_id,
                            stage_id,
                            boundary_id,
                            "control_flow_unavailable",
                        )
                    )
                    continue
                if _receiver_reassigned(
                    stage.function_body,
                    stage.statement_index,
                    boundary.statement_index,
                    stage.receiver_key,
                ):
                    diagnostics.append(
                        _diagnostic(
                            evidence.endpoint_id,
                            stage_id,
                            boundary_id,
                            "receiver_reassigned",
                        )
                    )
                    continue
                assert stage.receiver_hash is not None
                begin_occurrence_id = _nearest_begin(begins, contexts, stage)
                paths.append(
                    build_sql_transaction_ordered_path(
                        endpoint_id=evidence.endpoint_id,
                        file_path=stage.file_path,
                        function_name=stage.function_name,
                        receiver_hash=stage.receiver_hash,
                        begin_occurrence_id=begin_occurrence_id,
                        begin_scope=(
                            begin_scope_by_id[begin_occurrence_id]
                            if begin_occurrence_id is not None
                            else None
                        ),
                        stage_occurrence_id=stage_id,
                        boundary_occurrence_id=boundary_id,
                        boundary=boundary_kind,
                        limitations=(
                            *common_limitations,
                            (
                                "A reachable ordered flush may issue pending SQL but is not proof "
                                "of transaction commit or durable persistence."
                                if boundary_kind == "flush"
                                else "A reachable ordered commit or rollback is not proof of "
                                "boundary success or durable persistence."
                            ),
                        ),
                    )
                )
    unique_paths = {item.id: item for item in paths}
    unique_context_paths = {item.id: item for item in context_paths}
    unique_diagnostics = {
        (item.endpoint_id, item.stage_occurrence_id, item.boundary_occurrence_id): item
        for item in diagnostics
    }
    return build_sql_transaction_path_report(
        audit.provenance.audit_hash,
        transaction_report.report_hash,
        tuple(unique_paths.values()),
        tuple(unique_diagnostics.values()),
        context_paths=tuple(unique_context_paths.values()),
        source_projections=tuple(_fixture_source_projections(root, audit)),
        max_pairs=max_pairs,
    )
