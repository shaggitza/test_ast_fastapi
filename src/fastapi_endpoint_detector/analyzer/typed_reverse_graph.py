"""Snapshot-local typed impact graph with deterministic reverse evidence queries.

The builder consumes retained mypy module trees and source inventory directly. It
never calls ``analyze_endpoint`` and never starts from endpoint traversal.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any, Literal, Protocol

from mypy.nodes import (
    ARG_NAMED,
    ARG_POS,
    AssignmentStmt,
    CallExpr,
    Decorator,
    FuncDef,
    Import,
    ImportFrom,
    LambdaExpr,
    MemberExpr,
    NameExpr,
    Node,
    OperatorAssignmentStmt,
    TypeInfo,
    Var,
)

GraphSide = Literal["baseline", "target"]
EdgeKind = Literal["call", "constructor", "global_read", "global_write", "dependency"]


class TypedSnapshot(Protocol):
    """Structural boundary shared by the retained provider and analyzer snapshots."""

    modules: Any
    module_paths: Any
    report: Any
    type_maps: Any


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
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
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
        evidence: dict[tuple[str, str, str], ImpactEvidence] = {}
        uncertain_evidence: dict[tuple[str, str, str, str], PotentialImpactEvidence] = {}
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
                    confidence = _confidence((occurrence.confidence, *(e.confidence for e in path)))
                    exec_state = _join_execution(edge.execution_state for edge in path)
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
                    evidence[(occurrence.occurrence_id, seed.symbol, path_id)] = record
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
                uncertainty_queue: deque[
                    tuple[str, tuple[EdgeWitness, ...], frozenset[str]]
                ] = deque([(uncertainty.owner, (), frozenset({uncertainty.owner}))])
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
                        path_id = "/".join(edge.witness_id for edge in path)
                        record = PotentialImpactEvidence(
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
                                uncertainty.uncertainty_id,
                                path_id,
                            )
                        ] = record
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
                    item.uncertainty.uncertainty_id,
                    tuple(edge.witness_id for edge in item.supporting_witnesses),
                ),
            )
        )
        result_reasons = reasons | {
            reason for item in ordered for reason in item.incomplete.reasons
        }
        result_reasons.update(
            reason
            for item in ordered_uncertain
            for reason in item.incomplete.reasons
        )
        result_affected = affected | {
            item.seed.symbol
            for item in ordered
            if item.incomplete.reasons
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

    def _walk(self, node: Any) -> None:  # noqa: PLR0912
        if id(node) in self._seen:
            return
        self._seen.add(id(node))
        if isinstance(node, FuncDef):
            fullname = _fullname(node)
            if fullname and not fullname.startswith(self.module + "."):
                return
            previous_owner = self.owner
            fullname = fullname or previous_owner
            self.owner = fullname
            self.symbols[fullname] = self._symbol(fullname, "function", node)
            for child in _mypy_children(node):
                self._walk(child)
            self.owner = previous_owner
            return
        if isinstance(node, Decorator):
            fullname = _fullname(node) or _fullname(node.func)
            if fullname and not fullname.startswith(self.module + "."):
                return
            if fullname:
                self.symbols[fullname] = self._symbol(fullname, "function", node.func)
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

    def _record_call(self, node: CallExpr) -> None:
        target_node = getattr(node.callee, "node", None)
        target = _fullname(target_node)
        if isinstance(node.callee, NameExpr):
            target = self.import_aliases.get(node.callee.name, target)
        elif isinstance(node.callee, MemberExpr):
            imported_base = _expression_fullname(node.callee.expr, self.import_aliases)
            target = f"{imported_base}.{node.callee.name}" if imported_base else target
        kind: EdgeKind = "call"
        relation = "typed_call"
        confidence: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH"
        if isinstance(node.callee, LambdaExpr):
            target = f"{self.owner}.<lambda>@{node.callee.line}:{node.callee.column}"
            self._invoked_lambdas.add(id(node.callee))
            relation = "direct_lambda_invocation"
        resolved_target_node = self.definitions.get(target, target_node)
        if isinstance(resolved_target_node, TypeInfo):
            init = resolved_target_node.get("__init__")
            resolved_target_node = init.node if init is not None else None
            target = _fullname(resolved_target_node)
            kind, relation = "constructor", "typed_constructor"
            if target is None:
                confidence = "LOW"
        if target and _is_project_symbol(target, self.module_ids):
            span = self._span(node)
            receiver = (
                _expression_fullname(node.callee.expr, self.import_aliases)
                if isinstance(node.callee, MemberExpr)
                else None
            )
            arguments = _argument_bindings(
                node,
                resolved_target_node,
                type_maps=self.type_maps,
                skip_receiver=kind == "constructor"
                or (receiver is not None and bool(getattr(resolved_target_node, "info", None))),
            )
            edge = self._edge(
                self.owner,
                target,
                kind,
                span,
                confidence,
                self.execution_state,
                "invocation",
                relation,
                arguments,
                receiver,
            )
            self.edges.append(edge)
            self.symbols.setdefault(self.owner, self._symbol(self.owner, "function", node))
            if isinstance(node.callee, MemberExpr):
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
        elif not isinstance(node.callee, LambdaExpr):
            spelling = _call_spelling(node.callee)
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
        span = self._span(node) if node is not None and getattr(node, "line", 0) else None
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
    ) -> EdgeWitness:
        environment = tuple(
            (argument.formal_name, argument.expression_fullname)
            for argument in arguments
            if argument.formal_name and argument.expression_fullname
        )
        material = (caller, callee, kind, span, relation, arguments, receiver_fullname, environment)
        witness_id = hashlib.sha256(repr(material).encode()).hexdigest()
        return EdgeWitness(
            witness_id,
            caller,
            callee,
            kind,
            span,
            confidence,
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
        raw = resolved.read_bytes()
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
        uncertainties.update(
            (item.uncertainty_id, item) for item in walker.uncertainties
        )
    source_by_path = {
        str(Path(module_paths[module]).resolve()): digest for module, digest in source_hashes
    }
    module_by_path = {path: module for module, path in module_paths.items()}
    built_spans = (
        *(symbol.span for symbol in symbols.values() if symbol.span is not None),
        *(edge.span for edge in edges.values()),
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
                "LOW",
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
        3,
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
            "DI callable-value transfer from route parameter/default/Depends is not integrated",
            "finite receiver dispatch beyond mypy's direct typed target is not integrated",
            "assigned/returned lambda state is unknown; only direct invocation is classified",
            "effect/reference/deferred generator summaries are not integrated",
            "conditional route confidence must be supplied on endpoint occurrence bindings",
        ),
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


def _expression_fullname(expression: Any, aliases: dict[str, str]) -> str | None:
    if isinstance(expression, NameExpr):
        return aliases.get(expression.name, _fullname(getattr(expression, "node", None)))
    if isinstance(expression, MemberExpr):
        base = _expression_fullname(expression.expr, aliases)
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


def _is_project_symbol(fullname: str, module_ids: frozenset[str]) -> bool:
    return any(fullname.startswith(module + ".") for module in module_ids)


def _argument_bindings(
    call: CallExpr,
    target: Any,
    *,
    type_maps: Any,
    skip_receiver: bool = False,
) -> tuple[ArgumentBinding, ...]:
    args: list[ArgumentBinding] = []
    callable_node = getattr(target, "node", target)
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
                _expression_fullname(call.callee.expr, {})
                if isinstance(call.callee, MemberExpr)
                else None,
                None,
                _render_type(formal_types[0]) if formal_types else None,
            )
        )
    pos = 0
    for index, (expr, kind, name) in enumerate(
        zip(call.args, call.arg_kinds, call.arg_names, strict=True)
    ):
        positional = pos if kind == ARG_POS else None
        keyword = name if kind == ARG_NAMED else None
        formal_index = pos + offset
        formal = (
            name
            if keyword
            else arg_names[formal_index]
            if positional is not None and formal_index < len(arg_names)
            else None
        )
        actual_type = _render_type(type_maps.get(expr)) if hasattr(type_maps, "get") else None
        formal_index = arg_names.index(formal) if formal in arg_names else None
        formal_type = (
            _render_type(formal_types[formal_index])
            if formal_index is not None and formal_index < len(formal_types)
            else None
        )
        value = (
            _fullname(getattr(expr, "node", None))
            if isinstance(expr, (NameExpr, MemberExpr))
            else None
        )
        args.append(
            ArgumentBinding(index, formal, positional, keyword, value, actual_type, formal_type)
        )
        if kind == ARG_POS:
            pos += 1
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


def _confidence(values: Any) -> Literal["HIGH", "MEDIUM", "LOW"]:
    return max(values, key={"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get, default="LOW")


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


def _evidence_key(item: ImpactEvidence) -> tuple[str, str, str, str]:
    return (
        item.occurrence.occurrence_id,
        item.side,
        item.seed.symbol,
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
        try:
            for record in sorted(inventory.files, key=lambda item: item.module):
                path = Path(record.path)
                if path.is_symlink():
                    return False
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
                if (root / record.relative_path).resolve(strict=True) != resolved:
                    return False
                digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
                if digest != record.sha256:
                    return False
                current.append((record.module, digest))
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
        return (
            tuple(current) == graph.source_hashes
            and graph.schema_version == 3
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
            ):
                seeds.add(ChangedSeed(side, symbol.fullname, span))
    return tuple(sorted(seeds, key=_seed_key))
