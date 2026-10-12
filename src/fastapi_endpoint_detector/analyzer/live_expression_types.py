"""Bounded current-expression inference evidence for incremental comparisons.

The retained type-map size and the legacy AST/call snapshot keep their existing
meanings. This projection follows explicit source syntax edges, excluding
symbol backreferences, analyzed expansions, signature Type fields and PEP 695
TypeParam objects. Owned module TypeVar-like declarations are inventoried
separately. It is not a complete semantic-type or annotation equivalence proof.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

from mypy.nodes import Expression, MypyFile, Node, TypeVarLikeExpr
from mypy.types import ExtraAttrs, Type

LIVE_EXPRESSION_SCOPE = "current-source-expression-types-and-owned-typevars-v1"


class ExpressionSnapshotError(ValueError):
    """Current expression evidence cannot be compared within audited bounds."""


@dataclass(frozen=True)
class ExpressionSnapshotLimits:
    modules: int = 4096
    nodes_per_module: int = 100_000
    total_nodes: int = 1_000_000
    expressions: int = 500_000
    work_items: int = 4_000_000
    container_items: int = 100_000
    syntax_depth: int = 512
    type_items: int = 100_000
    type_depth: int = 48
    json_items: int = 100_000
    json_depth: int = 128
    string_chars: int = 262_144
    encoded_bytes: int = 32_000_000

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ExpressionSnapshotError(f"invalid snapshot limit: {field.name}")


@dataclass(frozen=True)
class ModuleExpressionTypes:
    module: str
    tree_present: bool
    expressions: int
    mapped_expressions: int
    owned_typevars: int
    sha256: str


# Explicit syntax edges audited against Mypy 1.19.1 and 2.4.0 visitors.
# Imports are leaves: their assignments are semantic-analysis replacements.
_SYNTAX_FIELDS: dict[str, tuple[str, ...]] = {
    "MypyFile": ("defs",),
    "Block": ("body",),
    "Argument": ("initializer",),
    "FuncDef": ("arguments", "body"),
    "LambdaExpr": ("arguments", "body"),
    "OverloadedFuncDef": ("items", "impl"),
    "Decorator": ("func", "decorators"),
    "ClassDef": ("decorators", "base_type_exprs", "metaclass", "keywords", "defs"),
    "ExpressionStmt": ("expr",),
    "AssignmentStmt": ("rvalue", "lvalues"),
    "OperatorAssignmentStmt": ("rvalue", "lvalue"),
    "WhileStmt": ("expr", "body", "else_body"),
    "ForStmt": ("index", "expr", "body", "else_body"),
    "ReturnStmt": ("expr",),
    "AssertStmt": ("expr", "msg"),
    "DelStmt": ("expr",),
    "IfStmt": ("expr", "body", "else_body"),
    "RaiseStmt": ("expr", "from_expr"),
    "TryStmt": ("body", "types", "vars", "handlers", "else_body", "finally_body"),
    "WithStmt": ("expr", "target", "body"),
    "MatchStmt": ("subject", "patterns", "guards", "bodies"),
    "TypeAliasStmt": ("name", "value"),
    "MemberExpr": ("expr",),
    "YieldFromExpr": ("expr",),
    "YieldExpr": ("expr",),
    "CallExpr": ("callee", "args"),
    "OpExpr": ("left", "right"),
    "ComparisonExpr": ("operands",),
    "SliceExpr": ("begin_index", "end_index", "stride"),
    "CastExpr": ("expr",),
    "AssertTypeExpr": ("expr",),
    "RevealExpr": ("expr",),
    "AssignmentExpr": ("target", "value"),
    "UnaryExpr": ("expr",),
    "ListExpr": ("items",),
    "TupleExpr": ("items",),
    "DictExpr": ("items",),
    "SetExpr": ("items",),
    "IndexExpr": ("base", "index"),
    "GeneratorExpr": ("sequences", "indices", "condlists", "left_expr"),
    "DictionaryComprehension": ("sequences", "indices", "condlists", "key", "value"),
    "ListComprehension": ("generator",),
    "SetComprehension": ("generator",),
    "ConditionalExpr": ("cond", "if_expr", "else_expr"),
    "TypeApplication": ("expr",),
    "StarExpr": ("expr",),
    "AwaitExpr": ("expr",),
    "SuperExpr": ("call",),
    "AsPattern": ("pattern", "name"),
    "OrPattern": ("patterns",),
    "ValuePattern": ("expr",),
    "SequencePattern": ("patterns",),
    "StarredPattern": ("capture",),
    "MappingPattern": ("keys", "values", "rest"),
    "ClassPattern": ("class_ref", "positionals", "keyword_values"),
}
_SYNTAX_LEAVES = frozenset(
    [
        "NameExpr",
        "StrExpr",
        "IntExpr",
        "FloatExpr",
        "BytesExpr",
        "ComplexExpr",
        "EllipsisExpr",
        "Var",
        "ContinueStmt",
        "PassStmt",
        "BreakStmt",
        "TempNode",
        "NonlocalDecl",
        "GlobalDecl",
        "Import",
        "ImportFrom",
        "ImportAll",
        "TypeVarExpr",
        "ParamSpecExpr",
        "TypeVarTupleExpr",
        "TypeAliasExpr",
        "TypeAlias",
        "NamedTupleExpr",
        "TypedDictExpr",
        "NewTypeExpr",
        "PromoteExpr",
        "EnumCallExpr",
        "SingletonPattern",
        "TypeFormExpr",
    ]
)
# Recursive fields used by audited cache-serializable Type shapes.
_TYPE_FIELDS: dict[str, tuple[str, ...]] = {
    "AnyType": ("source_any",),
    "UninhabitedType": (),
    "NoneType": (),
    "DeletedType": (),
    "EllipsisType": (),
    "Instance": ("args", "last_known_value"),
    "TypeAliasType": ("args",),
    "TypeVarType": ("values", "upper_bound", "default"),
    "ParamSpecType": ("upper_bound", "default", "prefix"),
    "TypeVarTupleType": ("upper_bound", "default", "tuple_fallback"),
    "UnboundType": ("args",),
    "UnpackType": ("type",),
    "Parameters": ("arg_types", "variables"),
    "CallableType": ("arg_types", "ret_type", "fallback", "variables", "type_guard", "type_is"),
    "Overloaded": ("_items",),
    "TupleType": ("items", "partial_fallback"),
    "TypedDictType": ("items", "fallback"),
    "LiteralType": ("fallback",),
    "UnionType": ("items",),
    "TypeType": ("item",),
}


@dataclass
class _Budget:
    limits: ExpressionSnapshotLimits
    work: int = 0
    nodes: int = 0
    expressions: int = 0
    encoded: int = 0

    def spend(self) -> None:
        self.work += 1
        if self.work > self.limits.work_items:
            raise ExpressionSnapshotError("snapshot work-item limit exceeded")


def _field(value: object, name: str) -> Any:
    try:
        return getattr(value, name)
    except (AttributeError, RuntimeError) as exc:
        raise ExpressionSnapshotError(f"unavailable snapshot field: {name}") from exc


def _container(value: object, budget: _Budget) -> list[object]:
    if isinstance(value, dict):
        if len(value) > budget.limits.container_items or any(type(key) is not str for key in value):
            raise ExpressionSnapshotError("unsupported or oversized snapshot dictionary")
        return [value[key] for key in sorted(value)]
    if isinstance(value, (tuple, list)):
        if len(value) > budget.limits.container_items:
            raise ExpressionSnapshotError("snapshot container-item limit exceeded")
        return list(value)
    raise ExpressionSnapshotError("unsupported snapshot container")


def _template_children(value: Node, budget: _Budget) -> list[object]:
    children: list[object] = []
    for item in _container(_field(value, "items"), budget):
        budget.spend()
        if isinstance(item, Expression):
            children.append(item)
            continue
        if not isinstance(item, tuple) or len(item) != 4:
            raise ExpressionSnapshotError("invalid template-string interpolation")
        expr, source_text, conversion, format_spec = item
        if (
            not isinstance(expr, Expression)
            or type(source_text) is not str
            or len(source_text) > budget.limits.string_chars
            or (conversion is not None and type(conversion) is not str)
            or (format_spec is not None and not isinstance(format_spec, Expression))
        ):
            raise ExpressionSnapshotError("invalid template-string interpolation")
        children.append(expr)
        if format_spec is not None:
            children.append(format_spec)
    return children


def _node_children(value: Node, budget: _Budget) -> list[object]:
    cls = type(value)
    if cls.__module__ not in {"mypy.nodes", "mypy.patterns"}:
        raise ExpressionSnapshotError("unsupported source-syntax node owner")
    if cls.__name__ == "TemplateStrExpr":
        return _template_children(value, budget)
    if cls.__name__ in _SYNTAX_FIELDS:
        return [_field(value, name) for name in _SYNTAX_FIELDS[cls.__name__]]
    if cls.__name__ in _SYNTAX_LEAVES:
        return []
    raise ExpressionSnapshotError(f"unsupported source-syntax node: {cls.__name__}")


def _syntax_expressions(tree: MypyFile, module: str, budget: _Budget) -> list[Expression]:
    pending: list[tuple[object, int, bool]] = [(tree, 0, False)]
    active: set[int] = set()
    seen: set[int] = set()
    expressions: list[Expression] = []
    nodes = 0
    while pending:
        value, depth, leaving = pending.pop()
        if leaving:
            active.remove(id(value))
            continue
        budget.spend()
        if depth > budget.limits.syntax_depth:
            raise ExpressionSnapshotError("snapshot syntax-depth limit exceeded")
        if value is None:
            continue
        if id(value) in active:
            raise ExpressionSnapshotError("cyclic current syntax")
        if id(value) in seen:
            continue
        if not isinstance(value, (Node, list, tuple, dict)):
            raise ExpressionSnapshotError("unsupported source-syntax child")
        active.add(id(value))
        seen.add(id(value))
        pending.append((value, depth, True))
        if not isinstance(value, Node):
            children = _container(value, budget)
        else:
            nodes += 1
            budget.nodes += 1
            if nodes > budget.limits.nodes_per_module or budget.nodes > budget.limits.total_nodes:
                raise ExpressionSnapshotError("snapshot node limit exceeded")
            children = _node_children(value, budget)
            if isinstance(value, Expression) and (
                not isinstance(value, TypeVarLikeExpr)
                or value.fullname.rpartition(".")[0] == module
            ):
                expressions.append(value)
        if len(children) + len(pending) > budget.limits.work_items - budget.work:
            raise ExpressionSnapshotError("snapshot pending-work limit exceeded")
        pending.extend((child, depth + 1, False) for child in reversed(children))
    return expressions


def _extra_attrs_children(value: object, budget: _Budget) -> list[object]:
    """Audit Instance metadata before Mypy's recursive ExtraAttrs serialization."""
    if type(value) is not ExtraAttrs:
        raise ExpressionSnapshotError("unsupported Instance.extra_attrs shape")
    attrs = _field(value, "attrs")
    immutable = _field(value, "immutable")
    mod_name = _field(value, "mod_name")
    if type(attrs) is not dict or len(attrs) > budget.limits.container_items:
        raise ExpressionSnapshotError("invalid or oversized ExtraAttrs.attrs")
    if type(immutable) is not set or len(immutable) > budget.limits.container_items:
        raise ExpressionSnapshotError("invalid or oversized ExtraAttrs.immutable")
    if mod_name is not None and (
        type(mod_name) is not str or len(mod_name) > budget.limits.string_chars
    ):
        raise ExpressionSnapshotError("invalid or oversized ExtraAttrs.mod_name")
    for name, typ in attrs.items():
        budget.spend()
        if (
            type(name) is not str
            or len(name) > budget.limits.string_chars
            or not isinstance(typ, Type)
        ):
            raise ExpressionSnapshotError("invalid ExtraAttrs attribute")
    for name in immutable:
        budget.spend()
        if type(name) is not str or len(name) > budget.limits.string_chars:
            raise ExpressionSnapshotError("invalid ExtraAttrs immutable name")
    return [attrs[name] for name in sorted(attrs)]


def _type_children(child: object, budget: _Budget) -> list[object]:
    if isinstance(child, Type):
        cls = type(child)
        if cls.__module__ != "mypy.types" or cls.__name__ not in _TYPE_FIELDS:
            raise ExpressionSnapshotError(f"unsupported expression type: {cls.__name__}")
        children = [_field(child, name) for name in _TYPE_FIELDS[cls.__name__]]
        if cls.__name__ == "Instance":
            extra = _field(child, "extra_attrs")
            if extra is not None:
                children.extend(_extra_attrs_children(extra, budget))
        if cls.__name__ == "CallableType" and hasattr(child, "instance_type"):
            children.append(_field(child, "instance_type"))
        return children
    if isinstance(child, (tuple, list, dict)):
        return _container(child, budget)
    raise ExpressionSnapshotError("unsupported expression type child")


def _serialize_type(value: Type, budget: _Budget) -> object:
    if not isinstance(value, Type):
        raise ExpressionSnapshotError("type map contains a non-Type value")
    pending: list[tuple[object, int, bool]] = [(value, 0, False)]
    active: set[int] = set()
    items = 0
    while pending:
        child, depth, leaving = pending.pop()
        if leaving:
            active.remove(id(child))
            continue
        budget.spend()
        items += 1
        if items > budget.limits.type_items or depth > budget.limits.type_depth:
            raise ExpressionSnapshotError("expression type traversal limit exceeded")
        if child is None:
            continue
        if id(child) in active:
            raise ExpressionSnapshotError("cyclic expression type")
        active.add(id(child))
        pending.append((child, depth, True))
        children = _type_children(child, budget)
        if len(children) + len(pending) > budget.limits.work_items - budget.work:
            raise ExpressionSnapshotError("expression type pending-work limit exceeded")
        pending.extend((item, depth + 1, False) for item in reversed(children))
    try:
        return value.serialize()
    except (AssertionError, NotImplementedError, RuntimeError, TypeError, ValueError) as exc:
        raise ExpressionSnapshotError("expression type cannot be serialized") from exc


def _json_children(child: object, budget: _Budget) -> list[object] | None:
    if child is None or type(child) in {bool, int}:
        return None
    if type(child) is str:
        if len(child) > budget.limits.string_chars:
            raise ExpressionSnapshotError("expression JSON string limit exceeded")
        return None
    if not isinstance(child, (tuple, list, dict)):
        raise ExpressionSnapshotError("non-JSON expression evidence")
    children = _container(child, budget)
    if isinstance(child, dict):
        children.extend(child.keys())
    return children


def _json_bytes(value: object, budget: _Budget) -> bytes:
    pending: list[tuple[object, int, bool]] = [(value, 0, False)]
    active: set[int] = set()
    items = 0
    while pending:
        child, depth, leaving = pending.pop()
        if leaving:
            active.remove(id(child))
            continue
        budget.spend()
        items += 1
        if items > budget.limits.json_items or depth > budget.limits.json_depth:
            raise ExpressionSnapshotError("expression JSON traversal limit exceeded")
        children = _json_children(child, budget)
        if children is None:
            continue
        if id(child) in active:
            raise ExpressionSnapshotError("cyclic expression JSON")
        active.add(id(child))
        pending.append((child, depth, True))
        if len(children) + len(pending) > budget.limits.work_items - budget.work:
            raise ExpressionSnapshotError("expression JSON pending-work limit exceeded")
        pending.extend((item, depth + 1, False) for item in reversed(children))
    chunks: list[bytes] = []
    try:
        for chunk in json.JSONEncoder(
            sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).iterencode(value):
            encoded = chunk.encode("utf-8")
            budget.encoded += len(encoded)
            if budget.encoded > budget.limits.encoded_bytes:
                raise ExpressionSnapshotError("snapshot encoded-byte limit exceeded")
            chunks.append(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ExpressionSnapshotError):
            raise
        raise ExpressionSnapshotError("expression evidence cannot be JSON encoded") from exc
    return b"".join(chunks)


def _owned_typevars(tree: MypyFile, module: str, budget: _Budget) -> list[TypeVarLikeExpr]:
    names = _field(tree, "names")
    if not isinstance(names, dict) or len(names) > budget.limits.container_items:
        raise ExpressionSnapshotError("unavailable or oversized module symbol table")
    if any(type(name) is not str for name in names):
        raise ExpressionSnapshotError("invalid module symbol name")
    declarations: list[TypeVarLikeExpr] = []
    for name in sorted(names):
        budget.spend()
        node = _field(names[name], "node")
        if (
            isinstance(node, TypeVarLikeExpr)
            and node.name == name
            and node.fullname == module + "." + name
        ):
            declarations.append(node)
    return declarations


def live_expression_type_snapshot(
    modules: Mapping[str, Any],
    type_map: Mapping[Expression, Type],
    *,
    limits: ExpressionSnapshotLimits | None = None,
) -> tuple[ModuleExpressionTypes, ...]:
    """Never enumerate retained map keys or report partial evidence as success.

    Missing entries are explicit markers. Serialized TypeVar allocator IDs stay
    strict. Unsupported/cyclic/oversized evidence raises and fails the gate.
    """
    budget = _Budget(limits or ExpressionSnapshotLimits())
    if len(modules) > budget.limits.modules:
        raise ExpressionSnapshotError("snapshot module limit exceeded")
    if any(type(module) is not str or not module or len(module) > 1024 for module in modules):
        raise ExpressionSnapshotError("invalid snapshot module identity")
    results: list[ModuleExpressionTypes] = []
    for module in sorted(modules):
        tree = _field(modules[module], "tree")
        if tree is not None and not isinstance(tree, MypyFile):
            raise ExpressionSnapshotError("module tree is not a MypyFile")
        digest = hashlib.sha256()
        digest.update(_json_bytes([LIVE_EXPRESSION_SCOPE, module, tree is not None], budget))
        expressions: list[Expression] = []
        declarations: list[TypeVarLikeExpr] = []
        if tree is not None:
            expressions = _syntax_expressions(tree, module, budget)
            declarations = _owned_typevars(tree, module, budget)
            expression_ids = {id(expr) for expr in expressions}
            expressions.extend(node for node in declarations if id(node) not in expression_ids)
        mapped = 0
        for ordinal, expr in enumerate(expressions):
            budget.expressions += 1
            if budget.expressions > budget.limits.expressions:
                raise ExpressionSnapshotError("snapshot expression limit exceeded")
            position = (expr.line, expr.column, expr.end_line, expr.end_column)
            if any(value is not None and type(value) is not int for value in position):
                raise ExpressionSnapshotError("invalid expression source position")
            present = expr in type_map
            typ = _serialize_type(type_map[expr], budget) if present else None
            mapped += int(present)
            digest.update(b"\n")
            digest.update(
                _json_bytes([ordinal, type(expr).__name__, position, present, typ], budget)
            )
        for declaration in declarations:
            types = {
                name: _serialize_type(_field(declaration, name), budget)
                for name in ("upper_bound", "default")
            }
            if hasattr(declaration, "values"):
                values = _field(declaration, "values")
                if len(values) > budget.limits.container_items:
                    raise ExpressionSnapshotError("TypeVar values limit exceeded")
                types["values"] = [_serialize_type(value, budget) for value in values]
            digest.update(b"\n")
            digest.update(
                _json_bytes(
                    [
                        "owned-typevar",
                        type(declaration).__name__,
                        declaration.fullname,
                        declaration.variance,
                        types,
                    ],
                    budget,
                )
            )
        results.append(
            ModuleExpressionTypes(
                module,
                tree is not None,
                len(expressions),
                mapped,
                len(declarations),
                digest.hexdigest(),
            )
        )
    return tuple(results)
