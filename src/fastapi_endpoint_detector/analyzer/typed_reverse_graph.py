"""Snapshot-local typed impact graph with deterministic reverse evidence queries.

The builder consumes retained mypy module trees and source inventory directly. It
never calls ``analyze_endpoint`` and never starts from endpoint traversal.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from collections.abc import Iterable  # noqa: TC003
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any, Literal, Protocol

from mypy.nodes import (
    ARG_NAMED,
    ARG_NAMED_OPT,
    ARG_OPT,
    ARG_POS,
    ARG_STAR,
    ARG_STAR2,
    AssignmentStmt,
    Block,
    CallExpr,
    Decorator,
    ForStmt,
    FuncDef,
    IfStmt,
    Import,
    ImportFrom,
    LambdaExpr,
    MatchStmt,
    MemberExpr,
    NameExpr,
    Node,
    OperatorAssignmentStmt,
    RaiseStmt,
    ReturnStmt,
    TryStmt,
    TypeInfo,
    Var,
    WhileStmt,
    WithStmt,
)

GraphSide = Literal["baseline", "target"]
SourceDependencyScope = Literal["signature", "app", "router", "include", "route"]
SourceDeclarationScope = Literal["app", "router", "include", "route"]
EdgeKind = Literal["call", "constructor", "global_read", "global_write", "dependency"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]
Invocation = Literal["function", "instance_method", "class_method", "constructor", "unknown"]
_GRAPH_SCHEMA_VERSION = 8


class TypedSnapshot(Protocol):
    """Structural boundary shared by the retained provider and analyzer snapshots."""

    @property
    def modules(self) -> Any: ...

    @property
    def module_paths(self) -> Any: ...

    @property
    def report(self) -> Any: ...

    @property
    def type_maps(self) -> Any: ...


@dataclass(frozen=True, order=True)
class SourceSpan:
    module: str
    path: str
    source_sha256: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int


@dataclass(frozen=True, order=True)
class Symbol:
    module: str
    fullname: str
    kind: str
    span: SourceSpan | None


@dataclass(frozen=True, order=True)
class ArgumentBinding:
    source_index: int
    formal_name: str | None
    positional_index: int | None
    keyword: str | None
    expression_fullname: str | None
    actual_type: str | None = None
    formal_type: str | None = None


@dataclass(frozen=True, order=True)
class EdgeWitness:
    witness_id: str
    caller: str
    callee: str
    kind: EdgeKind
    span: SourceSpan
    target_span: SourceSpan | None
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    invocation: Invocation
    execution_state: Literal["executed", "deferred", "unknown"]
    reference_state: Literal["reference", "invocation", "unknown"]
    relation: str
    arguments: tuple[ArgumentBinding, ...] = ()
    receiver_fullname: str | None = None
    environment: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, order=True)
class UncertaintyWitness:
    """Typed source-backed relation the snapshot graph cannot safely resolve."""

    uncertainty_id: str
    owner: str
    span: SourceSpan
    category: Literal[
        "unknown_binding",
        "virtual_dispatch",
        "deferred_callable",
        "dependency_injection",
        "effect_summary",
        "source_coverage",
    ]
    reason_code: str
    source_spelling: str
    occurrence_id: str = ""


@dataclass(frozen=True)
class SourceDependencyBinding:
    """Caller-supplied source declaration with execution and transfer unverified."""

    occurrence_id: str
    owner_symbol: str
    provider_symbol: str
    selector: Literal[
        "fastapi.params.Depends",
        "fastapi.params.Security",
        "fastapi.param_functions.Depends",
        "fastapi.param_functions.Security",
    ]
    call_span: SourceSpan
    target_span: SourceSpan


@dataclass(frozen=True)
class SourceDependencyUncertainty:
    """An unresolved source declaration owned by one physical route occurrence."""

    occurrence_id: str
    owner_symbol: str
    span: SourceSpan
    reason_code: str
    source_spelling: str
    scope: SourceDependencyScope = "signature"


@dataclass(frozen=True, order=True)
class SourceDependencyDeclarationSite:
    """Caller-associated native declaration; origin and route transfer are unverified."""

    occurrence_id: str
    owner_symbol: str
    scope: SourceDeclarationScope
    span: SourceSpan


@dataclass(frozen=True)
class EndpointOccurrenceBinding:
    """One physical route occurrence; equal handlers remain separate rows."""

    occurrence_id: str
    endpoint_id: str
    symbol: str
    span: SourceSpan
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH"
    binding_kind: Literal["handler", "dependency"] = "handler"
    dependency_symbols: tuple[str, ...] = ()
    conditional: bool = False

    def __post_init__(self) -> None:
        if self.conditional and self.confidence != "LOW":
            object.__setattr__(self, "confidence", "LOW")


@dataclass(frozen=True)
class ChangedSeed:
    side: GraphSide
    symbol: str
    span: SourceSpan | None = None
    occurrence_id: str | None = None


@dataclass(frozen=True)
class TraversalBudgets:
    nodes: int = 100_000
    depth: int = 10_000
    enqueues: int = 500_000
    frontier: int = 100_000
    witnesses: int = 500_000


@dataclass(frozen=True)
class Incompleteness:
    capped: bool = False
    reasons: tuple[str, ...] = ()
    affected_seeds: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImpactEvidence:
    side: GraphSide
    occurrence: EndpointOccurrenceBinding
    seed: ChangedSeed
    witnesses: tuple[EdgeWitness, ...]
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    execution_state: Literal["executed", "deferred", "unknown"]
    reference_state: Literal["reference", "invocation", "unknown"]
    depth: int
    incomplete: Incompleteness
    uncertainties: tuple[UncertaintyWitness, ...] = ()


@dataclass(frozen=True)
class PotentialImpactEvidence:
    """LOW-only route candidate whose changed-symbol relation is unresolved."""

    side: GraphSide
    occurrence: EndpointOccurrenceBinding
    seed: ChangedSeed
    uncertainty: UncertaintyWitness
    supporting_witnesses: tuple[EdgeWitness, ...]
    incomplete: Incompleteness
    confidence: Literal["LOW"] = "LOW"
    execution_state: Literal["unknown"] = "unknown"
    reference_state: Literal["unknown"] = "unknown"


@dataclass(frozen=True)
class ReverseQueryResult:
    evidence: tuple[ImpactEvidence, ...]
    incomplete: Incompleteness
    visited_nodes: int
    enqueued_nodes: int
    examined_witnesses: int
    uncertain_evidence: tuple[PotentialImpactEvidence, ...] = ()


@dataclass(frozen=True)
class TypedReverseGraph:
    schema_version: int
    root: str
    inventory_fingerprint: str
    source_hashes: tuple[tuple[str, str], ...]
    engine: str
    engine_version: str
    config_fingerprint: str
    graph_provenance: str
    symbols: tuple[Symbol, ...]
    edges: tuple[EdgeWitness, ...]
    endpoint_bindings: tuple[EndpointOccurrenceBinding, ...]
    uncertainties: tuple[UncertaintyWitness, ...] = ()
    limitations: tuple[str, ...] = ()
    source_dependency_bindings: tuple[SourceDependencyBinding, ...] = ()
    source_dependency_uncertainties: tuple[SourceDependencyUncertainty, ...] = ()
    source_dependency_declaration_sites: tuple[SourceDependencyDeclarationSite, ...] = ()

    def reverse_index(self) -> dict[str, tuple[EdgeWitness, ...]]:
        rows: dict[str, list[EdgeWitness]] = {}
        for edge in self.edges:
            rows.setdefault(edge.callee, []).append(edge)
        return {
            key: tuple(sorted(value, key=lambda edge: edge.witness_id))
            for key, value in rows.items()
        }

    def query(  # noqa: PLR0912, PLR0915
        self,
        seeds: tuple[ChangedSeed, ...] | list[ChangedSeed],
        *,
        side: GraphSide,
        budgets: TraversalBudgets | None = None,
    ) -> ReverseQueryResult:
        """Walk reverse callers from changed symbols, retaining every physical path."""
        budgets = budgets or TraversalBudgets()
        index = self.reverse_index()
        bindings = tuple(binding for binding in self.endpoint_bindings)
        by_symbol: dict[str, list[EndpointOccurrenceBinding]] = {}
        for binding in bindings:
            by_symbol.setdefault(binding.symbol, []).append(binding)
        evidence: dict[tuple[str, str, str, str], ImpactEvidence] = {}
        uncertain_evidence: dict[tuple[str, str, str, str, str], PotentialImpactEvidence] = {}
        uncertainties_by_owner: dict[str, tuple[UncertaintyWitness, ...]] = {}
        for item in self.uncertainties:
            uncertainties_by_owner.setdefault(item.owner, ())
            uncertainties_by_owner[item.owner] += (item,)
        reasons: set[str] = set()
        affected: set[str] = set()
        visited_count = enqueued_count = witness_count = 0
        visited_symbols: set[str] = set()
        for seed in sorted((item for item in seeds if item.side == side), key=_seed_key):
            # SCC safety is path-local; keeping depth in the state permits distinct
            # reconvergent physical witnesses while suppressing cycles.
            queue: deque[tuple[str, tuple[EdgeWitness, ...], frozenset[str]]] = deque(
                [(seed.symbol, (), frozenset({seed.symbol}))]
            )
            seen_states: set[tuple[str, tuple[str, ...]]] = set()
            while queue:
                if len(queue) > budgets.frontier:
                    reasons.add("frontier_budget")
                    affected.add(seed.symbol)
                    break
                current, path, path_symbols = queue.popleft()
                state_key = (current, tuple(edge.witness_id for edge in path))
                if state_key in seen_states:
                    continue
                seen_states.add(state_key)
                if current not in visited_symbols:
                    visited_symbols.add(current)
                    visited_count += 1
                if len(visited_symbols) > budgets.nodes:
                    reasons.add("node_budget")
                    affected.add(seed.symbol)
                    break
                for occurrence in sorted(by_symbol.get(current, ()), key=_binding_key):
                    if seed.occurrence_id and seed.occurrence_id != occurrence.occurrence_id:
                        continue
                    confidence = _confidence((occurrence.confidence, *(e.confidence for e in path)))
                    exec_state = _join_execution(edge.execution_state for edge in path)
                    if exec_state != "executed":
                        confidence = "LOW"
                    ref_state = _join_reference(edge.reference_state for edge in path)
                    path_owners = {
                        occurrence.symbol,
                        seed.symbol,
                        *(edge.caller for edge in path),
                    }
                    path_uncertainties = tuple(
                        sorted(
                            uncertainty
                            for owner in path_owners
                            for uncertainty in uncertainties_by_owner.get(owner, ())
                            if not uncertainty.occurrence_id
                            or uncertainty.occurrence_id == occurrence.occurrence_id
                        )
                    )
                    uncertainty_reasons = {item.reason_code for item in path_uncertainties}
                    incomplete = Incompleteness(
                        bool(reasons),
                        tuple(sorted(reasons | uncertainty_reasons)),
                        (seed.symbol,) if reasons or uncertainty_reasons else (),
                    )
                    record = ImpactEvidence(
                        side,
                        occurrence,
                        seed,
                        tuple(reversed(path)),
                        "LOW" if path_uncertainties and confidence == "HIGH" else confidence,
                        exec_state,
                        ref_state,
                        len(path),
                        incomplete,
                        path_uncertainties,
                    )
                    path_id = "/".join(edge.witness_id for edge in record.witnesses)
                    evidence[
                        (occurrence.occurrence_id, seed.symbol, seed.occurrence_id or "", path_id)
                    ] = record
                if len(path) >= budgets.depth:
                    if index.get(current):
                        reasons.add("depth_budget")
                        affected.add(seed.symbol)
                    continue
                for edge in index.get(current, ()):
                    witness_count += 1
                    if witness_count > budgets.witnesses:
                        reasons.add("witness_budget")
                        affected.add(seed.symbol)
                        break
                    if edge.caller in path_symbols:
                        continue
                    if enqueued_count >= budgets.enqueues:
                        reasons.add("enqueue_budget")
                        affected.add(seed.symbol)
                        break
                    queue.append((edge.caller, (*path, edge), path_symbols | {edge.caller}))
                    enqueued_count += 1
            # Unknown target/binding relations cannot be matched to a changed
            # fullname safely. Walk their exact callers backwards and report
            # separate LOW potential evidence rather than fabricating an edge.
            uncertain_capped = False
            for uncertainty in self.uncertainties:
                if uncertainty.category == "effect_summary":
                    continue
                if (
                    seed.occurrence_id
                    and uncertainty.occurrence_id
                    and seed.occurrence_id != uncertainty.occurrence_id
                ):
                    continue
                uncertainty_queue: deque[tuple[str, tuple[EdgeWitness, ...], frozenset[str]]] = (
                    deque([(uncertainty.owner, (), frozenset({uncertainty.owner}))])
                )
                uncertainty_seen: set[tuple[str, tuple[str, ...]]] = set()
                while uncertainty_queue:
                    if len(uncertainty_queue) > budgets.frontier:
                        reasons.add("frontier_budget")
                        affected.add(seed.symbol)
                        uncertain_capped = True
                        break
                    current, path, path_symbols = uncertainty_queue.popleft()
                    state_key = (current, tuple(edge.witness_id for edge in path))
                    if state_key in uncertainty_seen:
                        continue
                    uncertainty_seen.add(state_key)
                    if current not in visited_symbols:
                        visited_symbols.add(current)
                        visited_count += 1
                    if len(visited_symbols) > budgets.nodes:
                        reasons.add("node_budget")
                        affected.add(seed.symbol)
                        uncertain_capped = True
                        break
                    for occurrence in sorted(by_symbol.get(current, ()), key=_binding_key):
                        if seed.occurrence_id and seed.occurrence_id != occurrence.occurrence_id:
                            continue
                        if (
                            uncertainty.occurrence_id
                            and uncertainty.occurrence_id != occurrence.occurrence_id
                        ):
                            continue
                        path_id = "/".join(edge.witness_id for edge in path)
                        potential_record = PotentialImpactEvidence(
                            side,
                            occurrence,
                            seed,
                            uncertainty,
                            tuple(reversed(path)),
                            Incompleteness(
                                bool(reasons),
                                tuple(sorted(reasons | {uncertainty.reason_code})),
                                (seed.symbol,),
                            ),
                        )
                        uncertain_evidence[
                            (
                                occurrence.occurrence_id,
                                seed.symbol,
                                seed.occurrence_id or "",
                                uncertainty.uncertainty_id,
                                path_id,
                            )
                        ] = potential_record
                    if len(path) >= budgets.depth:
                        if index.get(current):
                            reasons.add("depth_budget")
                            affected.add(seed.symbol)
                            uncertain_capped = True
                        continue
                    for edge in index.get(current, ()):
                        witness_count += 1
                        if witness_count > budgets.witnesses:
                            reasons.add("witness_budget")
                            affected.add(seed.symbol)
                            uncertain_capped = True
                            break
                        if edge.caller in path_symbols:
                            continue
                        if enqueued_count >= budgets.enqueues:
                            reasons.add("enqueue_budget")
                            affected.add(seed.symbol)
                            uncertain_capped = True
                            break
                        uncertainty_queue.append(
                            (edge.caller, (*path, edge), path_symbols | {edge.caller})
                        )
                        enqueued_count += 1
                    if uncertain_capped:
                        break
                if uncertain_capped:
                    break
        if reasons:
            # Any returned evidence potentially depends on truncated traversal;
            # cap state is explicit on all evidence and the overall result.
            evidence = {
                key: ImpactEvidence(
                    value.side,
                    value.occurrence,
                    value.seed,
                    value.witnesses,
                    "LOW" if value.confidence == "HIGH" else value.confidence,
                    value.execution_state,
                    value.reference_state,
                    value.depth,
                    Incompleteness(
                        True,
                        tuple(sorted(set(value.incomplete.reasons) | reasons)),
                        tuple(sorted(set(value.incomplete.affected_seeds) | affected)),
                    ),
                    value.uncertainties,
                )
                for key, value in evidence.items()
            }
            uncertain_evidence = {
                key: PotentialImpactEvidence(
                    value.side,
                    value.occurrence,
                    value.seed,
                    value.uncertainty,
                    value.supporting_witnesses,
                    Incompleteness(
                        True,
                        tuple(sorted(set(value.incomplete.reasons) | reasons)),
                        tuple(sorted(set(value.incomplete.affected_seeds) | affected)),
                    ),
                )
                for key, value in uncertain_evidence.items()
            }
        ordered = tuple(sorted(evidence.values(), key=_evidence_key))
        ordered_uncertain = tuple(
            sorted(
                uncertain_evidence.values(),
                key=lambda item: (
                    item.occurrence.occurrence_id,
                    item.side,
                    item.seed.symbol,
                    item.seed.occurrence_id or "",
                    item.uncertainty.uncertainty_id,
                    tuple(edge.witness_id for edge in item.supporting_witnesses),
                ),
            )
        )
        result_reasons = reasons | {
            reason for item in ordered for reason in item.incomplete.reasons
        }
        result_reasons.update(
            reason for item in ordered_uncertain for reason in item.incomplete.reasons
        )
        result_affected = affected | {
            item.seed.symbol for item in ordered if item.incomplete.reasons
        }
        result_affected.update(item.seed.symbol for item in ordered_uncertain)
        return ReverseQueryResult(
            ordered,
            Incompleteness(
                bool(reasons),
                tuple(sorted(result_reasons)),
                tuple(sorted(result_affected)),
            ),
            visited_count,
            enqueued_count,
            witness_count,
            ordered_uncertain,
        )


class _ModuleWalker:
    """Collect typed call and global relation witnesses from one retained AST."""

    def __init__(
        self,
        module: str,
        path: str,
        digest: str,
        module_ids: frozenset[str],
        tree: Any,
        definitions: dict[str, Any],
        type_maps: Any,
    ) -> None:
        self.module = module
        self.path = path
        self.digest = digest
        self.module_ids = module_ids
        self.import_aliases = _module_import_aliases(tree, module, module_ids)
        self.definitions = definitions
        self.type_maps = type_maps
        self.owner = module
        self.symbols: dict[str, Symbol] = {}
        self.edges: list[EdgeWitness] = []
        self.uncertainties: list[UncertaintyWitness] = []
        self.execution_state: Literal["executed", "deferred", "unknown"] = "executed"
        self._seen: set[int] = set()
        self._invoked_lambdas: set[int] = set()
        self._call_callees: set[int] = set()
        self._write_names: set[int] = set()
        self._awaited_calls: set[int] = set()
        self._default_owner: str | None = None

    def visit_mypy_file(self, tree: Any) -> None:
        self._collect_invoked_lambdas(tree)
        self._walk(tree)

    def _collect_invoked_lambdas(self, tree: Any) -> None:
        if tree is None:
            return
        seen: set[int] = set()

        def collect(node: Any) -> None:
            if id(node) in seen:
                return
            seen.add(id(node))
            if isinstance(node, CallExpr) and isinstance(node.callee, LambdaExpr):
                self._invoked_lambdas.add(id(node.callee))
            if isinstance(node, CallExpr):
                self._call_callees.add(id(node.callee))
            # Only the exact scheduler form ``await async_function(...)`` proves
            # that the coroutine body is consumed. Stored/forwarded awaitables
            # remain unresolved and are reported LOW by the main walk.
            if type(node).__name__ == "AwaitExpr" and isinstance(node.expr, CallExpr):
                self._awaited_calls.add(id(node.expr))
            if isinstance(node, AssignmentStmt):
                for lvalue in node.lvalues:
                    self._collect_write_names(lvalue)
            elif isinstance(node, OperatorAssignmentStmt):
                self._collect_write_names(node.lvalue)
            for child in _mypy_children(node):
                collect(child)

        collect(tree)

    def _collect_write_names(self, node: Any) -> None:
        if isinstance(node, NameExpr):
            self._write_names.add(id(node))
        for child in _mypy_children(node):
            self._collect_write_names(child)

    def _walk(self, node: Any) -> None:  # noqa: PLR0911, PLR0912, PLR0915
        if id(node) in self._seen:
            return
        self._seen.add(id(node))
        if isinstance(node, FuncDef):
            fullname = _fullname(node)
            if fullname and "." in fullname and not fullname.startswith(self.module + "."):
                return
            previous_owner = self.owner
            if previous_owner != self.module and not (
                fullname and fullname.startswith(previous_owner + ".")
            ):
                fullname = f"{previous_owner}.{node.name}"
            else:
                fullname = fullname or previous_owner
            self.symbols[fullname] = self._symbol(fullname, "function", node)
            previous_execution_state = self.execution_state
            # Defaults execute when the definition is created; the function
            # body is a separate callable transfer and is walked under its own
            # symbol so callers can reach it through typed call edges.
            previous_default_owner = self._default_owner
            self._default_owner = fullname
            for argument in node.arguments:
                if argument.initializer is not None:
                    self._walk(argument.initializer)
            self._default_owner = previous_default_owner
            self.owner = fullname
            self._walk(node.body)
            self.owner = previous_owner
            self.execution_state = previous_execution_state
            return
        if isinstance(node, Block):
            for statement in node.body:
                self._walk(statement)
                if _statement_terminates(statement):
                    break
            return
        if isinstance(node, (ReturnStmt, RaiseStmt)):
            for child in _mypy_children(node):
                self._walk(child)
            return
        if isinstance(node, IfStmt):
            for index, (condition, body) in enumerate(zip(node.expr, node.body, strict=False)):
                self._walk(condition)
                truth = _static_truth(condition)
                if truth is True:
                    self._walk(body)
                    return
                if truth is None:
                    previous_state = self.execution_state
                    self.execution_state = "unknown"
                    for branch in node.body[index:]:
                        self._walk(branch)
                    if node.else_body is not None:
                        self._walk(node.else_body)
                    self.execution_state = previous_state
                    if _if_followup_is_unknown(node):
                        self.execution_state = _join_execution((previous_state, "unknown"))
                    return
            if node.else_body is not None:
                self._walk(node.else_body)
            return
        if isinstance(node, (ForStmt, MatchStmt, TryStmt, WhileStmt, WithStmt)):
            previous_state = self.execution_state
            self.execution_state = "unknown"
            self._record_uncertainty(
                self.owner,
                node,
                "source_coverage",
                "control_flow_transfer_not_imported",
                type(node).__name__,
            )
            for child in _mypy_children(node):
                self._walk(child)
            self.execution_state = previous_state
            return
        if isinstance(node, Decorator):
            fullname = _fullname(node) or _fullname(node.func)
            if fullname and "." in fullname and not fullname.startswith(self.module + "."):
                return
            if self.owner != self.module and not (
                fullname and fullname.startswith(self.owner + ".")
            ):
                fullname = f"{self.owner}.{node.func.name}"
            if fullname:
                self.symbols[fullname] = self._symbol(fullname, "function", node.func)
                if any(
                    not _is_route_registration_decorator(decorator)
                    for decorator in getattr(node, "decorators", ())
                ):
                    self._record_uncertainty(
                        fullname,
                        node,
                        "deferred_callable",
                        "decorator_transfer_not_imported",
                        "decorator_application",
                    )
            for child in _mypy_children(node):
                self._walk(child)
            return
        if isinstance(node, LambdaExpr):
            previous_owner = self.owner
            previous_state = self.execution_state
            lambda_name = f"{previous_owner}.<lambda>@{node.line}:{node.column}"
            invoked = id(node) in self._invoked_lambdas
            self.owner = lambda_name
            self.execution_state = "executed" if invoked else "deferred"
            if not invoked:
                self._record_uncertainty(
                    previous_owner,
                    node,
                    "deferred_callable",
                    "lambda_capture_not_proven_invoked",
                    "<lambda>",
                )
            self.symbols[lambda_name] = self._symbol(lambda_name, "lambda", node)
            for child in _mypy_children(node):
                self._walk(child)
            self.owner = previous_owner
            self.execution_state = previous_state
            return
        if isinstance(node, CallExpr):
            self._record_call(node)
        elif isinstance(node, NameExpr):
            self._record_name(node)
        for child in _mypy_children(node):
            self._walk(child)

    def _record_call(self, node: CallExpr) -> None:  # noqa: PLR0912, PLR0915
        target_node = getattr(node.callee, "node", None)
        target = _fullname(target_node)
        resolved_target_node: Any = target_node
        if isinstance(node.callee, NameExpr):
            target = self.import_aliases.get(node.callee.name, target)
            if (
                target
                and "." not in target
                and isinstance(target_node, (FuncDef, Decorator))
                and self.owner != self.module
            ):
                lexical_parent = self.owner.rsplit(".", maxsplit=1)[0]
                target = f"{lexical_parent}.{target}"
        elif isinstance(node.callee, MemberExpr):
            base_expression = node.callee.expr
            base_node = getattr(base_expression, "node", None)
            imported_base = _expression_fullname(base_expression, self.import_aliases, self.owner)
            if isinstance(base_node, TypeInfo):
                member_symbol = base_node.get(node.callee.name)
                resolved_target_node = getattr(member_symbol, "node", None)
                if isinstance(resolved_target_node, Decorator):
                    resolved_target_node = resolved_target_node.func
                target = _fullname(resolved_target_node)
            elif imported_base in self.module_ids:
                target = f"{imported_base}.{node.callee.name}"
                resolved_target_node = self.definitions.get(target)
                if not isinstance(resolved_target_node, (FuncDef, Decorator)):
                    target = None
            else:
                # An instance receiver's declared class is not a proven finite
                # runtime target. Leave the call unbound until the analyzer
                # exports its owned finite dispatch result.
                target = None
                resolved_target_node = None
        kind: EdgeKind = "call"
        relation = "typed_call"
        confidence: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH"
        invocation: Invocation = "function"
        if isinstance(node.callee, LambdaExpr):
            target = f"{self.owner}.<lambda>@{node.callee.line}:{node.callee.column}"
            self._invoked_lambdas.add(id(node.callee))
            relation = "direct_lambda_invocation"
        if target:
            resolved_target_node = self.definitions.get(target, resolved_target_node)
        if isinstance(resolved_target_node, TypeInfo):
            init = resolved_target_node.get("__init__")
            resolved_target_node = init.node if init is not None else None
            target = _fullname(resolved_target_node)
            kind, relation = "constructor", "typed_constructor"
            invocation = "constructor"
            if target is None:
                confidence = "LOW"
        elif isinstance(node.callee, MemberExpr):
            function_node = (
                resolved_target_node.func
                if isinstance(resolved_target_node, Decorator)
                else resolved_target_node
            )
            if isinstance(function_node, FuncDef):
                invocation = (
                    "class_method"
                    if function_node.is_class
                    else "function"
                    if function_node.is_static
                    else "instance_method"
                )
                resolved_target_node = function_node
            else:
                invocation = "unknown"
            if isinstance(base_node, TypeInfo) and invocation == "instance_method":
                # A class object does not supply the actual instance receiver;
                # unbound method calls need an explicit receiver binding API.
                target = None
                resolved_target_node = None
                invocation = "unknown"
        if target and _is_project_symbol(target, self.module_ids):
            async_target = (
                resolved_target_node.func
                if isinstance(resolved_target_node, Decorator)
                else resolved_target_node
            )
            is_coroutine = bool(getattr(async_target, "is_coroutine", False))
            is_generator = bool(
                getattr(async_target, "is_generator", False)
                or getattr(async_target, "is_async_generator", False)
            )
            if is_coroutine or is_generator:
                if is_coroutine and id(node) in self._awaited_calls:
                    call_execution: Literal["executed", "deferred", "unknown"] = "executed"
                else:
                    call_execution = "unknown"
                    self._record_uncertainty(
                        self.owner,
                        node,
                        "deferred_callable",
                        "async_result_not_directly_awaited"
                        if is_coroutine
                        else "generator_result_not_proven_consumed",
                        target,
                    )
            else:
                call_execution = self.execution_state
            span = self._span(node)
            receiver = (
                _expression_fullname(node.callee.expr, self.import_aliases, self.owner)
                if isinstance(node.callee, MemberExpr)
                else None
            )
            arguments = _argument_bindings(
                node,
                resolved_target_node,
                type_maps=self.type_maps,
                import_aliases=self.import_aliases,
                owner=self.owner,
                skip_receiver=kind == "constructor"
                or (receiver is not None and invocation in {"instance_method", "class_method"}),
            )
            edge = self._edge(
                self.owner,
                target,
                kind,
                span,
                confidence,
                call_execution,
                "invocation",
                relation,
                arguments,
                receiver,
                invocation=invocation,
                target_span=self._span(node.callee),
            )
            self.edges.append(edge)
            self.symbols.setdefault(self.owner, self._symbol(self.owner, "function", node))
            if isinstance(node.callee, MemberExpr) and invocation == "instance_method":
                self._record_uncertainty(
                    self.owner,
                    node,
                    "virtual_dispatch",
                    "finite_receiver_targets_not_imported",
                    node.callee.name,
                )
            self._record_uncertainty(
                self.owner,
                node,
                "effect_summary",
                "effect_transfer_not_imported",
                target,
            )
            if any(kind in {ARG_STAR, ARG_STAR2} for kind in node.arg_kinds):
                self._record_uncertainty(
                    self.owner,
                    node,
                    "unknown_binding",
                    "starred_actual_formal_binding_unresolved",
                    _call_spelling(node.callee),
                )
        elif not isinstance(node.callee, LambdaExpr):
            spelling = _call_spelling(node.callee)
            if spelling.rsplit(".", maxsplit=1)[-1] == "Depends":
                self._record_uncertainty(
                    self._default_owner or self.owner,
                    node,
                    "dependency_injection",
                    "dependency_parameter_transfer_not_proven",
                    spelling,
                )
            else:
                self._record_uncertainty(
                    self.owner,
                    node,
                    "unknown_binding",
                    "call_target_outside_typed_project_graph"
                    if target
                    else "typed_call_target_unavailable",
                    spelling,
                )
            if isinstance(node.callee, MemberExpr):
                self._record_uncertainty(
                    self.owner,
                    node,
                    "virtual_dispatch",
                    "member_target_unavailable_or_finite_targets_not_imported",
                    spelling,
                )

    def _record_uncertainty(
        self,
        owner: str,
        node: Node,
        category: Literal[
            "unknown_binding",
            "virtual_dispatch",
            "deferred_callable",
            "dependency_injection",
            "effect_summary",
            "source_coverage",
        ],
        reason_code: str,
        source_spelling: str,
    ) -> None:
        span = self._span(node)
        material = (owner, span, category, reason_code, source_spelling)
        identity = hashlib.sha256(repr(material).encode()).hexdigest()
        self.uncertainties.append(
            UncertaintyWitness(
                identity,
                owner,
                span,
                category,
                reason_code,
                source_spelling,
            )
        )

    def _record_name(self, node: NameExpr) -> None:
        if id(node) in self._call_callees:
            return
        symbol_node = getattr(node, "node", None)
        fullname = self.import_aliases.get(node.name, _fullname(symbol_node))
        if (
            isinstance(symbol_node, Var)
            and fullname
            and not (self.owner != self.module and fullname.startswith(self.owner + "."))
            and _is_project_symbol(fullname, self.module_ids)
        ):
            is_write = id(node) in self._write_names or bool(getattr(node, "is_def", False))
            edge_kind: EdgeKind = "global_write" if is_write else "global_read"
            edge = self._edge(
                self.owner,
                fullname,
                edge_kind,
                self._span(node),
                "HIGH",
                "executed",
                "reference",
                edge_kind,
                (),
            )
            self.edges.append(edge)
            self.symbols.setdefault(fullname, self._symbol(fullname, "global", symbol_node))

    def _span(self, node: Node) -> SourceSpan:
        line = int(getattr(node, "line", 0) or 0)
        column = int(getattr(node, "column", 0) or 0)
        raw_end_line = getattr(node, "end_line", None)
        raw_end_column = getattr(node, "end_column", None)
        end_line = int(raw_end_line if raw_end_line is not None else line)
        end_column = int(raw_end_column if raw_end_column is not None else column)
        return SourceSpan(
            self.module,
            self.path,
            self.digest,
            max(1, line),
            max(0, column),
            max(1, end_line),
            max(0, end_column),
        )

    def _symbol(self, fullname: str, kind: str, node: Any) -> Symbol:
        span = self._span(node) if node is not None and getattr(node, "line", None) else None
        return Symbol(self.module, fullname, kind, span)

    def _edge(
        self,
        caller: str,
        callee: str,
        kind: EdgeKind,
        span: SourceSpan,
        confidence: Literal["HIGH", "MEDIUM", "LOW"],
        state: Literal["executed", "deferred", "unknown"],
        reference: Literal["reference", "invocation", "unknown"],
        relation: str,
        arguments: tuple[ArgumentBinding, ...],
        receiver_fullname: str | None = None,
        *,
        invocation: Invocation = "unknown",
        target_span: SourceSpan | None = None,
    ) -> EdgeWitness:
        environment = tuple(
            (argument.formal_name, argument.expression_fullname)
            for argument in arguments
            if argument.formal_name and argument.expression_fullname
        )
        material = (
            caller,
            callee,
            kind,
            span,
            target_span,
            relation,
            arguments,
            invocation,
            receiver_fullname,
            environment,
        )
        witness_id = hashlib.sha256(repr(material).encode()).hexdigest()
        return EdgeWitness(
            witness_id,
            caller,
            callee,
            kind,
            span,
            target_span,
            confidence,
            invocation,
            state,
            reference,
            relation,
            arguments,
            receiver_fullname,
            environment,
        )


def build_typed_reverse_graph(  # noqa: PLR0912, PLR0915
    inventory: Any,
    typed_snapshot: TypedSnapshot,
    endpoint_bindings: tuple[EndpointOccurrenceBinding, ...] | list[EndpointOccurrenceBinding],
    *,
    config_fingerprint: str,
    source_snapshots: dict[str, bytes] | None = None,
    source_dependency_bindings: tuple[SourceDependencyBinding, ...]
    | list[SourceDependencyBinding] = (),
    source_dependency_uncertainties: tuple[SourceDependencyUncertainty, ...]
    | list[SourceDependencyUncertainty] = (),
    source_dependency_declaration_sites: tuple[SourceDependencyDeclarationSite, ...]
    | list[SourceDependencyDeclarationSite] = (),
) -> TypedReverseGraph:
    """Build one immutable typed graph from inventory bytes and retained mypy ASTs."""
    inventory_root = Path(inventory.root)
    if inventory_root.is_symlink():
        raise ValueError("symlink inventory root rejected")
    root = inventory_root.resolve(strict=True)
    records = tuple(sorted(inventory.files, key=lambda item: item.module))
    source_hashes: list[tuple[str, str]] = []
    source_lines: dict[str, tuple[bytes, ...]] = {}
    module_paths: dict[str, str] = {}
    for record in records:
        candidate = Path(record.path)
        if candidate.is_symlink():
            raise ValueError(f"symlink source rejected: {candidate}")
        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise ValueError(f"source path escapes inventory root: {candidate}") from error
        expected_path = (root / record.relative_path).resolve(strict=True)
        if expected_path != resolved:
            raise ValueError(f"inventory relative path mismatch: {record.module}")
        if record.module in module_paths or resolved.suffix != ".py":
            raise ValueError(f"invalid or duplicate canonical module identity: {record.module}")
        raw = (
            source_snapshots.get(record.module)
            if source_snapshots is not None
            else resolved.read_bytes()
        )
        if raw is None:
            raise ValueError(f"source snapshot is missing for {record.module}")
        digest = hashlib.sha256(raw).hexdigest()
        if digest != record.sha256:
            raise ValueError(f"source hash mismatch: {record.module}")
        source_hashes.append((record.module, digest))
        module_paths[record.module] = str(resolved)
        source_lines[str(resolved)] = tuple(raw.splitlines(keepends=True))
    typed_paths = {
        str(Path(path).resolve())
        for path in typed_snapshot.module_paths.values()
        if Path(path).suffix == ".py"
    }
    if not set(module_paths.values()).issubset(typed_paths):
        raise ValueError("typed snapshot does not cover the canonical inventory")
    module_ids = frozenset(module_paths)
    symbols: dict[str, Symbol] = {}
    edges: dict[str, EdgeWitness] = {}
    uncertainties: dict[str, UncertaintyWitness] = {}
    definitions: dict[str, Any] = {}
    for state in typed_snapshot.modules.values():
        tree = getattr(state, "tree", None)
        for table_node in getattr(tree, "names", {}).values():
            symbol_node = getattr(table_node, "node", None)
            fullname = _fullname(symbol_node)
            if fullname:
                definitions[fullname] = symbol_node
    for module in sorted(module_ids):
        state = typed_snapshot.modules.get(module)
        tree = getattr(state, "tree", None)
        if tree is None:
            raise ValueError(f"typed snapshot has no AST for module {module}")
        path = module_paths[module]
        digest = dict(source_hashes)[module]
        walker = _ModuleWalker(
            module,
            path,
            digest,
            module_ids,
            tree,
            definitions,
            typed_snapshot.type_maps,
        )
        walker.visit_mypy_file(tree)
        symbols.update(walker.symbols)
        edges.update((edge.witness_id, edge) for edge in walker.edges)
        uncertainties.update((item.uncertainty_id, item) for item in walker.uncertainties)
    source_by_path = {
        str(Path(module_paths[module]).resolve()): digest for module, digest in source_hashes
    }
    module_by_path = {path: module for module, path in module_paths.items()}
    built_spans = (
        *(symbol.span for symbol in symbols.values() if symbol.span is not None),
        *(span for edge in edges.values() for span in (edge.span, edge.target_span) if span),
        *(item.span for item in uncertainties.values()),
    )
    for span in built_spans:
        raw_lines = source_lines.get(str(Path(span.path).resolve()))
        if raw_lines is None or not _source_span_is_valid(span, raw_lines):
            raise ValueError(
                "typed AST emitted invalid source span: "
                f"{span.module}:{span.start_line}:{span.start_column}-"
                f"{span.end_line}:{span.end_column}"
            )
    for binding in endpoint_bindings:
        binding_path = str(Path(binding.span.path).resolve())
        lines = source_lines.get(binding_path, ())
        span_valid = _source_span_is_valid(binding.span, lines)
        if (
            binding_path not in source_by_path
            or source_by_path[binding_path] != binding.span.source_sha256
            or module_by_path.get(binding_path) != binding.span.module
            or not span_valid
            or binding.symbol not in symbols
            or any(dependency not in symbols for dependency in binding.dependency_symbols)
        ):
            raise ValueError(
                f"endpoint occurrence is not bound to this typed snapshot: {binding.occurrence_id}"
            )
        for dependency in sorted(set(binding.dependency_symbols)):
            edge_material = (
                binding.symbol,
                dependency,
                "dependency",
                binding.span,
                binding.occurrence_id,
            )
            identity = hashlib.sha256(repr(edge_material).encode()).hexdigest()
            edges[identity] = EdgeWitness(
                identity,
                binding.symbol,
                dependency,
                "dependency",
                binding.span,
                None,
                "LOW",
                "unknown",
                "executed",
                "invocation",
                "framework_dependency_binding",
            )
            uncertainty_id = hashlib.sha256(
                repr((edge_material, "dependency_parameter_transfer_not_proven")).encode()
            ).hexdigest()
            uncertainties[uncertainty_id] = UncertaintyWitness(
                uncertainty_id,
                binding.symbol,
                binding.span,
                "dependency_injection",
                "dependency_parameter_transfer_not_proven",
                dependency,
            )
    if (
        not isinstance(source_dependency_bindings, (tuple, list))
        or not isinstance(source_dependency_uncertainties, (tuple, list))
        or not isinstance(source_dependency_declaration_sites, (tuple, list))
    ):
        raise ValueError("source dependency metadata must be bounded rows")
    if (
        len(source_dependency_bindings) + len(source_dependency_uncertainties)
        > _MAX_SOURCE_DEPENDENCY_METADATA
        or len(source_dependency_declaration_sites) > _MAX_SOURCE_DEPENDENCY_METADATA
    ):
        raise ValueError("source dependency metadata exceeds row budget")
    raw_bindings = tuple(source_dependency_bindings)
    raw_uncertainties = tuple(source_dependency_uncertainties)
    raw_declaration_sites = tuple(source_dependency_declaration_sites)
    if not _dependency_metadata_valid(
        raw_bindings,
        raw_uncertainties,
        endpoint_bindings,
        symbols.values(),
        source_by_path,
        module_by_path,
        source_lines,
        declaration_sites=raw_declaration_sites,
    ):
        raise ValueError("source dependency metadata is not bound to this typed snapshot")
    dependency_bindings = tuple(sorted(raw_bindings, key=_dependency_binding_key))
    dependency_uncertainties = tuple(sorted(raw_uncertainties, key=_dependency_uncertainty_key))
    declaration_sites = tuple(sorted(raw_declaration_sites))
    dependency_edges, dependency_issues = _source_dependency_projection(
        dependency_bindings, dependency_uncertainties
    )
    for witness_id, witness in dependency_edges.items():
        if witness_id in edges and edges[witness_id] != witness:
            raise ValueError("source dependency witness identity collision")
        edges[witness_id] = witness
    for uncertainty_id, uncertainty in dependency_issues.items():
        if uncertainty_id in uncertainties and uncertainties[uncertainty_id] != uncertainty:
            raise ValueError("source dependency uncertainty identity collision")
        uncertainties[uncertainty_id] = uncertainty

    inventory_fingerprint = _sha256(
        tuple((item.module, item.relative_path, item.sha256) for item in records)
    )
    report = typed_snapshot.report
    engine = str(getattr(report, "engine", "mypy-fine-grained"))
    engine_version = str(getattr(report, "mypy_version", version("mypy")))
    provenance = str(getattr(report, "cache_fingerprint", ""))
    if not provenance:
        raise ValueError("typed snapshot lacks provider cache provenance")
    reported_sources = tuple(sorted(getattr(report, "source_digests_after", ())))
    if reported_sources != tuple(sorted(source_hashes)):
        raise ValueError("typed provider source digests do not match canonical inventory bytes")
    return TypedReverseGraph(
        _GRAPH_SCHEMA_VERSION,
        str(root),
        inventory_fingerprint,
        tuple(source_hashes),
        engine,
        engine_version,
        config_fingerprint,
        provenance,
        tuple(sorted(symbols.values())),
        tuple(sorted(edges.values(), key=lambda item: item.witness_id)),
        tuple(sorted(endpoint_bindings, key=_binding_key)),
        tuple(sorted(uncertainties.values())),
        (
            (
                "Depends/Security source metadata is LOW; execution and parameter transfer "
                "are unverified"
                if dependency_bindings or dependency_uncertainties
                else "DI callable-value transfer from route parameter/default/Depends "
                "is not integrated"
            ),
            "finite receiver dispatch beyond mypy's direct typed target is not integrated",
            "assigned/returned lambda state is unknown; only direct invocation is classified",
            "effect/reference/deferred generator summaries are not integrated",
            "conditional route confidence must be supplied on endpoint occurrence bindings",
        ),
        dependency_bindings,
        dependency_uncertainties,
        declaration_sites,
    )


def _fullname(node: Any) -> str | None:
    value = getattr(node, "fullname", None)
    return value if isinstance(value, str) and value else None


def _call_spelling(expression: Any) -> str:
    if isinstance(expression, NameExpr):
        return expression.name
    if isinstance(expression, MemberExpr):
        base = _call_spelling(expression.expr)
        return f"{base}.{expression.name}" if base else expression.name
    if isinstance(expression, LambdaExpr):
        return "<lambda>"
    return type(expression).__name__


def _source_span_is_valid(span: SourceSpan, lines: tuple[bytes, ...]) -> bool:
    if not (1 <= span.start_line <= span.end_line <= len(lines)):
        return False
    start_line = lines[span.start_line - 1].rstrip(b"\r\n")
    end_line = lines[span.end_line - 1].rstrip(b"\r\n")
    if span.start_column > len(start_line) or span.end_column > len(end_line):
        return False
    return (span.start_line, span.start_column) <= (span.end_line, span.end_column)


_MAX_SOURCE_DEPENDENCY_METADATA = 8192
_MAX_SOURCE_DECLARATION_BYTES = 65536
_MAX_SOURCE_DECLARATION_LINES = 1024
_SOURCE_DECLARATION_SCOPES = frozenset({"app", "router", "include", "route"})
_SOURCE_DEPENDENCY_SELECTORS = frozenset(
    {
        "fastapi.params.Depends",
        "fastapi.params.Security",
        "fastapi.param_functions.Depends",
        "fastapi.param_functions.Security",
    }
)


def _dependency_span_key(span: SourceSpan) -> tuple[Any, ...]:
    return (
        span.module,
        span.path,
        span.source_sha256,
        span.start_line,
        span.start_column,
        span.end_line,
        span.end_column,
    )


def _dependency_binding_key(row: SourceDependencyBinding) -> tuple[Any, ...]:
    return (
        row.occurrence_id,
        row.owner_symbol,
        row.provider_symbol,
        row.selector,
        _dependency_span_key(row.call_span),
        _dependency_span_key(row.target_span),
    )


def _dependency_uncertainty_key(row: SourceDependencyUncertainty) -> tuple[Any, ...]:
    return (
        row.occurrence_id,
        row.owner_symbol,
        _dependency_span_key(row.span),
        row.reason_code,
        row.source_spelling,
        row.scope,
    )


def _dependency_declaration_key(row: Any) -> tuple[Any, ...]:
    return row.occurrence_id, row.owner_symbol, row.scope, _dependency_span_key(row.span)


def _dependency_span_valid(
    span: Any,
    hashes: dict[str, str],
    modules: dict[str, str],
    lines: dict[str, tuple[bytes, ...]],
) -> bool:
    if (
        not isinstance(span, SourceSpan)
        or type(span.module) is not str
        or not span.module
        or type(span.path) is not str
        or not span.path
        or type(span.source_sha256) is not str
        or len(span.source_sha256) != 64
        or any(char not in "0123456789abcdef" for char in span.source_sha256)
        or any(
            type(value) is not int
            for value in (
                span.start_line,
                span.start_column,
                span.end_line,
                span.end_column,
            )
        )
        or span.start_line < 1
        or span.end_line < span.start_line
        or span.start_column < 0
        or span.end_column < 0
        or (span.start_line, span.start_column) >= (span.end_line, span.end_column)
    ):
        return False
    try:
        path = str(Path(span.path).resolve())
    except (OSError, ValueError):
        return False
    return (
        path == span.path
        and modules.get(path) == span.module
        and hashes.get(path) == span.source_sha256
        and _source_span_is_valid(span, lines.get(path, ()))
    )


def dependency_declaration_spelling(span: SourceSpan, lines: tuple[bytes, ...]) -> str | None:
    """Read a bounded declaration display from exact UTF-8 byte coordinates."""
    coordinates = (span.start_line, span.start_column, span.end_line, span.end_column)
    if (
        any(type(value) is not int for value in coordinates)
        or span.start_column < 0
        or span.end_column < 0
        or (span.start_line, span.start_column) >= (span.end_line, span.end_column)
        or not _source_span_is_valid(span, lines)
        or span.end_line - span.start_line + 1 > _MAX_SOURCE_DECLARATION_LINES
    ):
        return None
    first, last = lines[span.start_line - 1], lines[span.end_line - 1]
    try:
        first[: span.start_column].decode("utf-8")
        last[: span.end_column].decode("utf-8")
        parts: tuple[bytes, ...]
        if span.start_line == span.end_line:
            parts = (first[span.start_column : span.end_column],)
        else:
            parts = (
                first[span.start_column :],
                *lines[span.start_line : span.end_line - 1],
                last[: span.end_column],
            )
        if sum(len(part) for part in parts) > _MAX_SOURCE_DECLARATION_BYTES:
            return None
        spelling = b"".join(parts).decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    return spelling[:256] if spelling else None


def _source_dependency_projection(
    dependency_bindings: tuple[SourceDependencyBinding, ...],
    dependency_uncertainties: tuple[SourceDependencyUncertainty, ...],
) -> tuple[dict[str, EdgeWitness], dict[str, UncertaintyWitness]]:
    dependency_edges: dict[str, EdgeWitness] = {}
    dependency_issues: dict[str, UncertaintyWitness] = {}
    for row in dependency_bindings:
        physical = (
            row.owner_symbol,
            row.provider_symbol,
            row.selector,
            row.call_span,
            row.target_span,
        )
        witness_id = _sha256(("source-dependency-v1", physical))
        witness = EdgeWitness(
            witness_id,
            row.owner_symbol,
            row.provider_symbol,
            "dependency",
            row.call_span,
            row.target_span,
            "LOW",
            "unknown",
            "unknown",
            "unknown",
            "typed_source_dependency_binding",
        )
        if witness_id in dependency_edges and dependency_edges[witness_id] != witness:
            raise ValueError("source dependency witness identity collision")
        dependency_edges[witness_id] = witness
        uncertainty_id = _sha256(("source-dependency-transfer-v1", physical))
        dependency_issues[uncertainty_id] = UncertaintyWitness(
            uncertainty_id,
            row.owner_symbol,
            row.call_span,
            "dependency_injection",
            "dependency_parameter_transfer_not_proven",
            row.selector,
        )
    for uncertainty_row in dependency_uncertainties:
        uncertainty_physical = (
            uncertainty_row.owner_symbol,
            uncertainty_row.span,
            uncertainty_row.reason_code,
            uncertainty_row.source_spelling,
            uncertainty_row.scope,
            uncertainty_row.occurrence_id,
        )
        uncertainty_id = _sha256(("source-dependency-uncertainty-v1", uncertainty_physical))
        dependency_issues[uncertainty_id] = UncertaintyWitness(
            uncertainty_id,
            uncertainty_row.owner_symbol,
            uncertainty_row.span,
            "dependency_injection",
            uncertainty_row.reason_code,
            uncertainty_row.source_spelling,
            uncertainty_row.occurrence_id,
        )

    return dependency_edges, dependency_issues


def _dependency_projection_valid(
    graph: TypedReverseGraph, *, expected_graph: TypedReverseGraph
) -> bool:
    """Compare DI rows with an independently reconstructed typed-source projection."""
    if any(not isinstance(edge, EdgeWitness) for edge in graph.edges) or any(
        not isinstance(item, UncertaintyWitness) for item in graph.uncertainties
    ):
        return False
    relations = {"typed_source_dependency_binding", "framework_dependency_binding"}
    actual_edges = tuple(edge for edge in graph.edges if edge.relation in relations)
    expected_edges = tuple(edge for edge in expected_graph.edges if edge.relation in relations)
    actual_issues = tuple(
        item for item in graph.uncertainties if item.category == "dependency_injection"
    )
    expected_issues = tuple(
        item for item in expected_graph.uncertainties if item.category == "dependency_injection"
    )
    if len({edge.witness_id for edge in actual_edges}) != len(actual_edges) or len(
        {item.uncertainty_id for item in actual_issues}
    ) != len(actual_issues):
        return False
    return sorted(actual_edges, key=lambda edge: edge.witness_id) == sorted(
        expected_edges, key=lambda edge: edge.witness_id
    ) and sorted(actual_issues, key=lambda item: item.uncertainty_id) == sorted(
        expected_issues, key=lambda item: item.uncertainty_id
    )


def _dependency_metadata_valid(  # noqa: PLR0911, PLR0912
    bindings: tuple[Any, ...],
    uncertainties: tuple[Any, ...],
    endpoint_bindings: Iterable[Any],
    symbols: Iterable[Any],
    hashes: dict[str, str],
    modules: dict[str, str],
    lines: dict[str, tuple[bytes, ...]],
    *,
    declaration_sites: tuple[Any, ...] = (),
) -> bool:
    if (
        not isinstance(bindings, (tuple, list))
        or not isinstance(uncertainties, (tuple, list))
        or not isinstance(declaration_sites, (tuple, list))
    ):
        return False
    if not bindings and not uncertainties and not declaration_sites:
        return True
    if (
        len(bindings) + len(uncertainties) > _MAX_SOURCE_DEPENDENCY_METADATA
        or len(declaration_sites) > _MAX_SOURCE_DEPENDENCY_METADATA
    ):
        return False
    endpoints = tuple(endpoint_bindings)
    if any(
        not isinstance(row, EndpointOccurrenceBinding)
        or type(row.occurrence_id) is not str
        or not row.occurrence_id
        or type(row.symbol) is not str
        or not row.symbol
        or not _dependency_span_valid(row.span, hashes, modules, lines)
        for row in endpoints
    ):
        return False
    occurrences = {row.occurrence_id: row for row in endpoints}
    if len(occurrences) != len(endpoints):
        return False
    symbol_rows = tuple(symbols)
    if any(not isinstance(row, Symbol) or type(row.fullname) is not str for row in symbol_rows):
        return False
    by_symbol = {row.fullname: row for row in symbol_rows}

    def owner_identity_valid(occurrence_id: str, owner_name: str) -> bool:
        occurrence = occurrences.get(occurrence_id)
        owner = by_symbol.get(owner_name)
        return (
            occurrence is not None
            and owner is not None
            and owner.kind == "function"
            and occurrence.symbol == owner_name
            and occurrence.span == owner.span
            and _dependency_span_valid(owner.span, hashes, modules, lines)
        )

    def owner_valid(occurrence_id: str, owner_name: str, span: SourceSpan) -> bool:
        if not owner_identity_valid(occurrence_id, owner_name):
            return False
        owner_span = by_symbol[owner_name].span
        return (
            isinstance(owner_span, SourceSpan)
            and span.module == owner_span.module
            and span.path == owner_span.path
            and span.source_sha256 == owner_span.source_sha256
            and (owner_span.start_line, owner_span.start_column)
            <= (span.start_line, span.start_column)
            and (span.end_line, span.end_column) <= (owner_span.end_line, owner_span.end_column)
        )

    eligible_sites: set[tuple[Any, ...]] = set()
    for site in declaration_sites:
        if (
            not isinstance(site, SourceDependencyDeclarationSite)
            or type(site.occurrence_id) is not str
            or not site.occurrence_id
            or type(site.owner_symbol) is not str
            or not site.owner_symbol
            or type(site.scope) is not str
            or site.scope not in _SOURCE_DECLARATION_SCOPES
            or not owner_identity_valid(site.occurrence_id, site.owner_symbol)
            or not _dependency_span_valid(site.span, hashes, modules, lines)
            or dependency_declaration_spelling(site.span, lines[site.span.path]) is None
        ):
            return False
        key = _dependency_declaration_key(site)
        if key in eligible_sites:
            return False
        eligible_sites.add(key)

    seen: set[tuple[Any, ...]] = set()
    for row in bindings:
        if not isinstance(row, SourceDependencyBinding):
            return False
        if (
            type(row.occurrence_id) is not str
            or not row.occurrence_id
            or type(row.owner_symbol) is not str
            or not row.owner_symbol
            or type(row.provider_symbol) is not str
            or not row.provider_symbol
            or type(row.selector) is not str
            or row.selector not in _SOURCE_DEPENDENCY_SELECTORS
            or not _dependency_span_valid(row.call_span, hashes, modules, lines)
            or not _dependency_span_valid(row.target_span, hashes, modules, lines)
            or not owner_valid(row.occurrence_id, row.owner_symbol, row.call_span)
        ):
            return False
        target = by_symbol.get(row.provider_symbol)
        if target is None or target.kind != "function" or target.span != row.target_span:
            return False
        key = _dependency_binding_key(row)
        if key in seen:
            return False
        seen.add(key)
    seen.clear()
    used_sites: set[tuple[Any, ...]] = set()
    for row in uncertainties:
        if not isinstance(row, SourceDependencyUncertainty):
            return False
        if (
            type(row.occurrence_id) is not str
            or not row.occurrence_id
            or type(row.owner_symbol) is not str
            or not row.owner_symbol
            or type(row.reason_code) is not str
            or not row.reason_code
            or len(row.reason_code) > 96
            or not row.reason_code.replace("_", "").isalnum()
            or type(row.source_spelling) is not str
            or len(row.source_spelling) > 256
            or not _dependency_span_valid(row.span, hashes, modules, lines)
            or type(row.scope) is not str
            or row.scope not in {"signature", *_SOURCE_DECLARATION_SCOPES}
            or (
                row.scope == "signature"
                and not owner_valid(row.occurrence_id, row.owner_symbol, row.span)
            )
            or (
                row.scope != "signature"
                and (
                    row.reason_code != "route_dependency_association_origin_and_transfer_unverified"
                    or _dependency_declaration_key(row) not in eligible_sites
                    or row.source_spelling
                    != dependency_declaration_spelling(row.span, lines[row.span.path])
                )
            )
        ):
            return False
        if row.scope != "signature":
            used_sites.add(_dependency_declaration_key(row))
        key = _dependency_uncertainty_key(row)
        if key in seen:
            return False
        seen.add(key)
    return used_sites == eligible_sites


def _module_import_aliases(tree: Any, module: str, module_ids: frozenset[str]) -> dict[str, str]:
    """Resolve only explicit imports whose destination is an exact inventory module."""
    aliases: dict[str, str] = {}
    for definition in getattr(tree, "defs", ()):
        if isinstance(definition, ImportFrom):
            imported = definition.id
            sibling = (
                f"{module.rsplit('.', maxsplit=1)[0]}.{imported}" if "." in module else imported
            )
            target_module = sibling if sibling in module_ids else imported
            if target_module not in module_ids:
                continue
            for original, alias in definition.names:
                aliases[alias or original] = f"{target_module}.{original}"
        elif isinstance(definition, Import):
            for imported, alias in definition.ids:
                if imported in module_ids:
                    aliases[alias or imported] = imported
    return aliases


def _expression_fullname(
    expression: Any, aliases: dict[str, str], owner: str | None = None
) -> str | None:
    if isinstance(expression, NameExpr):
        value = aliases.get(expression.name, _fullname(getattr(expression, "node", None)))
        if value and "." not in value and owner:
            return f"{owner}.{value}"
        return value
    if isinstance(expression, MemberExpr):
        base = _expression_fullname(expression.expr, aliases, owner)
        return f"{base}.{expression.name}" if base else None
    return None


_IGNORED_MYPY_FIELDS = frozenset(
    {
        "node",
        "info",
        "type",
        "unanalyzed_type",
        "original_def",
        "original_first_arg",
        "def_var",
        "expanded",
        "analyzed",
    }
)


def _mypy_children(node: Any) -> tuple[Any, ...]:
    """Read structural AST fields without following symbol/type backreferences."""
    children: list[Any] = []
    for cls in type(node).__mro__:
        for field_name in getattr(cls, "__mypyc_attrs__", ()):
            if field_name.startswith("_") or field_name in _IGNORED_MYPY_FIELDS:
                continue
            try:
                value = getattr(node, field_name)
            except (AttributeError, RuntimeError):
                continue
            if isinstance(value, (tuple, list)):
                children.extend(item for item in value if hasattr(type(item), "__mypyc_attrs__"))
            elif hasattr(type(value), "__mypyc_attrs__"):
                children.append(value)
    return tuple(children)


def _static_truth(node: Any) -> bool | None:  # noqa: PLR0911
    """Resolve only literal conditions; all other control flow stays unknown."""
    kind = type(node).__name__
    if kind == "NameExpr":
        fullname = getattr(node, "fullname", None)
        if fullname == "builtins.True":
            return True
        if fullname == "builtins.False":
            return False
    if kind == "BoolExpr":
        values = [_static_truth(value) for value in node.values]
        if node.op == "and" and False in values:
            return False
        if node.op == "or" and True in values:
            return True
        if all(value is not None for value in values):
            return all(values) if node.op == "and" else any(values)
    if kind in {"IntExpr", "FloatExpr", "StrExpr", "BytesExpr"}:
        value = getattr(node, "value", None)
        if isinstance(value, (bool, int, float, str, bytes)):
            return bool(value)
    if kind == "UnaryExpr" and getattr(node, "op", None) == "not":
        value = _static_truth(node.expr)
        return None if value is None else not value
    return None


def _is_route_registration_decorator(node: Any) -> bool:
    expression = node.callee if isinstance(node, CallExpr) else node
    return isinstance(expression, MemberExpr) and expression.name in {
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "options",
        "head",
        "route",
        "api_route",
        "websocket",
    }


def _statement_terminates(node: Any) -> bool:
    """Recognize only unconditional return/raise paths in a bounded block walk."""
    if isinstance(node, (ReturnStmt, RaiseStmt)):
        return True
    if not isinstance(node, IfStmt):
        return False
    for index, (condition, branch) in enumerate(zip(node.expr, node.body, strict=False)):
        truth = _static_truth(condition)
        if truth is True:
            return _block_terminates(branch)
        if truth is None:
            remaining = (*node.body[index + 1 :], node.else_body)
            return all(_block_terminates(item) for item in (branch, *remaining))
    return _block_terminates(node.else_body)


def _block_terminates(node: Any) -> bool:
    return isinstance(node, Block) and bool(node.body) and _statement_terminates(node.body[-1])


def _if_followup_is_unknown(node: IfStmt) -> bool:
    possible: list[Any] = []
    unknown_seen = False
    for index, (condition, branch) in enumerate(zip(node.expr, node.body, strict=False)):
        truth = _static_truth(condition)
        if truth is False:
            continue
        possible.append(branch)
        if truth is True:
            break
        unknown_seen = True
        possible.extend(node.body[index + 1 :])
        break
    if not unknown_seen:
        return False
    possible.append(node.else_body)
    terminated = [_block_terminates(branch) for branch in possible]
    return any(terminated) and not all(terminated)


def _is_project_symbol(fullname: str, module_ids: frozenset[str]) -> bool:
    return any(fullname.startswith(module + ".") for module in module_ids)


def _argument_bindings(
    call: CallExpr,
    target: Any,
    *,
    type_maps: Any,
    import_aliases: dict[str, str],
    owner: str,
    skip_receiver: bool = False,
) -> tuple[ArgumentBinding, ...]:
    args: list[ArgumentBinding] = []
    callable_node = (
        target.func if isinstance(target, Decorator) else getattr(target, "node", target)
    )
    arg_names = tuple(getattr(callable_node, "arg_names", ()) or ())
    callable_type = getattr(callable_node, "type", None)
    formal_types = tuple(getattr(callable_type, "arg_types", ()) or ())
    offset = 1 if skip_receiver and arg_names else 0
    if offset:
        args.append(
            ArgumentBinding(
                -1,
                arg_names[0],
                None,
                None,
                _expression_fullname(call.callee.expr, import_aliases, owner)
                if isinstance(call.callee, MemberExpr)
                else None,
                None,
                _render_type(formal_types[0]) if formal_types else None,
            )
        )
    pos = 0
    positional_uncertain = False
    positional_kinds = {ARG_POS, ARG_OPT}
    keyword_kinds = {ARG_NAMED, ARG_NAMED_OPT}
    for index, (expr, kind, name) in enumerate(
        zip(call.args, call.arg_kinds, call.arg_names, strict=True)
    ):
        positional = pos if kind in positional_kinds and not positional_uncertain else None
        keyword = name if kind in keyword_kinds else None
        formal_index = pos + offset
        formal = (
            name
            if keyword in arg_names
            else None
            if keyword is not None
            else arg_names[formal_index]
            if positional is not None and formal_index < len(arg_names)
            else None
        )
        actual_type = _render_type(type_maps.get(expr)) if hasattr(type_maps, "get") else None
        bound_formal_index = arg_names.index(formal) if formal in arg_names else None
        formal_type = (
            _render_type(formal_types[bound_formal_index])
            if bound_formal_index is not None and bound_formal_index < len(formal_types)
            else None
        )
        value = (
            _expression_fullname(expr, import_aliases, owner)
            if isinstance(expr, (NameExpr, MemberExpr))
            else None
        )
        args.append(
            ArgumentBinding(index, formal, positional, keyword, value, actual_type, formal_type)
        )
        if kind in positional_kinds and not positional_uncertain:
            pos += 1
        elif kind == ARG_STAR:
            positional_uncertain = True
    return tuple(args)


def _render_type(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    return rendered or None


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _seed_key(seed: ChangedSeed) -> tuple[str, str, str]:
    return seed.side, seed.symbol, seed.occurrence_id or ""


def _binding_key(binding: EndpointOccurrenceBinding) -> tuple[str, str, str, int, int]:
    return (
        binding.occurrence_id,
        binding.endpoint_id,
        binding.symbol,
        binding.span.start_line,
        binding.span.start_column,
    )


def _confidence(values: Iterable[Confidence]) -> Confidence:
    rank: dict[Confidence, int] = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return max(values, key=rank.__getitem__, default="LOW")


def _join_execution(values: Any) -> Literal["executed", "deferred", "unknown"]:
    states = set(values)
    return (
        "unknown"
        if not states or "unknown" in states
        else "deferred"
        if "deferred" in states
        else "executed"
    )


def _join_reference(values: Any) -> Literal["reference", "invocation", "unknown"]:
    states = set(values)
    return (
        "unknown"
        if not states or "unknown" in states
        else "reference"
        if "reference" in states
        else "invocation"
    )


def _evidence_key(item: ImpactEvidence) -> tuple[str, str, str, str, str]:
    return (
        item.occurrence.occurrence_id,
        item.side,
        item.seed.symbol,
        item.seed.occurrence_id or "",
        "/".join(e.witness_id for e in item.witnesses),
    )


@dataclass(frozen=True)
class GraphCacheManifest:
    schema_version: int
    root: str
    inventory_fingerprint: str
    source_hashes: tuple[tuple[str, str], ...]
    engine: str
    engine_version: str
    config_fingerprint: str
    graph_provenance: str
    source_dependency_bindings: tuple[SourceDependencyBinding, ...] = ()
    source_dependency_uncertainties: tuple[SourceDependencyUncertainty, ...] = ()
    source_dependency_declaration_sites: tuple[SourceDependencyDeclarationSite, ...] = ()


class TypedGraphCache:
    """Strict fail-closed JSON cache manifest validation; graph stays snapshot local."""

    @staticmethod
    def manifest(graph: TypedReverseGraph) -> GraphCacheManifest:
        return GraphCacheManifest(
            graph.schema_version,
            graph.root,
            graph.inventory_fingerprint,
            graph.source_hashes,
            graph.engine,
            graph.engine_version,
            graph.config_fingerprint,
            graph.graph_provenance,
            graph.source_dependency_bindings,
            graph.source_dependency_uncertainties,
            graph.source_dependency_declaration_sites,
        )

    @staticmethod
    def cache_key(graph: TypedReverseGraph) -> str:
        """Bind a reusable graph identity to every input that can change edges."""
        return _sha256(TypedGraphCache.manifest(graph))

    @staticmethod
    def validate(  # noqa: PLR0911
        graph: TypedReverseGraph,
        inventory: Any,
        typed_snapshot: TypedSnapshot,
        *,
        config_fingerprint: str,
    ) -> bool:
        inventory_root = Path(inventory.root)
        if inventory_root.is_symlink():
            return False
        try:
            root = inventory_root.resolve(strict=True)
        except OSError:
            return False
        if str(root) != graph.root or graph.config_fingerprint != config_fingerprint:
            return False
        current: list[tuple[str, str]] = []
        current_bytes: dict[str, bytes] = {}
        current_paths: dict[str, str] = {}
        try:
            for record in sorted(inventory.files, key=lambda item: item.module):
                path = Path(record.path)
                if path.is_symlink():
                    return False
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
                if (root / record.relative_path).resolve(strict=True) != resolved:
                    return False
                raw = resolved.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                if digest != record.sha256:
                    return False
                current.append((record.module, digest))
                current_bytes[record.module] = raw
                current_paths[record.module] = str(resolved)
        except (OSError, ValueError):
            return False
        inventory_fingerprint = _sha256(
            tuple(
                (record.module, record.relative_path, record.sha256)
                for record in sorted(inventory.files, key=lambda item: item.module)
            )
        )
        report = typed_snapshot.report
        snapshot_provenance = str(getattr(report, "cache_fingerprint", ""))
        snapshot_engine = str(getattr(report, "engine", "mypy-fine-grained"))
        snapshot_version = str(getattr(report, "mypy_version", version("mypy")))
        snapshot_sources = tuple(sorted(getattr(report, "source_digests_after", ())))
        try:
            snapshot_paths = {
                str(Path(path).resolve(strict=True))
                for path in typed_snapshot.module_paths.values()
                if Path(path).suffix == ".py"
            }
            inventoried_paths = {
                str(Path(record.path).resolve(strict=True)) for record in inventory.files
            }
        except (OSError, ValueError):
            return False
        current_by_path = {current_paths[module]: digest for module, digest in current}
        module_by_path = {path: module for module, path in current_paths.items()}
        current_lines = {
            current_paths[module]: tuple(raw.splitlines(keepends=True))
            for module, raw in current_bytes.items()
        }
        metadata_valid = _dependency_metadata_valid(
            graph.source_dependency_bindings,
            graph.source_dependency_uncertainties,
            graph.endpoint_bindings,
            graph.symbols,
            current_by_path,
            module_by_path,
            current_lines,
            declaration_sites=graph.source_dependency_declaration_sites,
        )
        if not metadata_valid:
            return False
        try:
            expected_graph = build_typed_reverse_graph(
                inventory,
                typed_snapshot,
                graph.endpoint_bindings,
                config_fingerprint=config_fingerprint,
                source_snapshots=current_bytes,
                source_dependency_bindings=graph.source_dependency_bindings,
                source_dependency_uncertainties=graph.source_dependency_uncertainties,
                source_dependency_declaration_sites=graph.source_dependency_declaration_sites,
            )
        except (OSError, ValueError):
            return False
        return (
            _dependency_projection_valid(graph, expected_graph=expected_graph)
            and tuple(current) == graph.source_hashes
            and graph.schema_version == _GRAPH_SCHEMA_VERSION
            and graph.inventory_fingerprint == inventory_fingerprint
            and inventoried_paths.issubset(snapshot_paths)
            and bool(snapshot_provenance)
            and graph.graph_provenance == snapshot_provenance
            and snapshot_sources == graph.source_hashes
            and graph.engine == snapshot_engine
            and graph.engine_version == snapshot_version == version("mypy")
        )


def seeds_for_changed_coordinates(
    side: GraphSide,
    changed: tuple[tuple[str, int, int], ...] | list[tuple[str, int, int]],
    graph: TypedReverseGraph,
    *,
    occurrence_id: str | None = None,
) -> tuple[ChangedSeed, ...]:
    """Map exact path/line/column changes to graph symbols; no basename matching."""
    seeds: set[ChangedSeed] = set()
    for path, line, column in changed:
        canonical = str(Path(path).resolve())
        for symbol in graph.symbols:
            span = symbol.span
            if (
                span
                and span.path == canonical
                and span.start_line <= line <= span.end_line
                and (line != span.start_line or column >= span.start_column)
                and (line != span.end_line or column <= span.end_column)
            ):
                seeds.add(ChangedSeed(side, symbol.fullname, span, occurrence_id))
    return tuple(sorted(seeds, key=_seed_key))
