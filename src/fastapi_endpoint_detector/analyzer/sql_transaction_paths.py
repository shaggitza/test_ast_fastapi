"""Bounded source-backed SQL stage-to-boundary ordering diagnostics."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from fastapi_endpoint_detector.models.sql_transaction import (
    SQLTransactionContextPath,
    SQLTransactionOrderedPath,
    SQLTransactionPathDiagnostic,
    SQLTransactionPathError,
    SQLTransactionPathReport,
    build_sql_transaction_context_path,
    build_sql_transaction_ordered_path,
    build_sql_transaction_path_report,
)

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

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

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.qualname: list[str] = []
        self.calls: dict[tuple[int, int, int, int], _SourceCall] = {}

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
        receiver_key = (
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

    def _record_context(
        self,
        statement: ast.With | ast.AsyncWith,
        function_name: str,
        statement_index: int,
        function_body: tuple[ast.stmt, ...],
    ) -> None:
        if len(statement.items) != 1 or statement.items[0].optional_vars is not None:
            return
        begin = _unwrap_call(statement.items[0].context_expr)
        if begin is None:
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


def _load_call_index(root: Path, file_path: str) -> dict[tuple[int, int, int, int], _SourceCall]:
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
    indexer = _CallIndexer(file_path)
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
    indexes = {file_path: _load_call_index(root, file_path) for file_path in sorted(files)}
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
        max_pairs=max_pairs,
    )
