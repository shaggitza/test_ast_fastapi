"""Own in-memory node controls; no parsed app or provider build is needed."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from mypy import nodes as mypy_nodes
from mypy.nodes import (
    GDEF,
    Block,
    CallExpr,
    ClassDef,
    Expression,
    ExpressionStmt,
    FuncDef,
    ListExpr,
    MypyFile,
    NameExpr,
    ReturnStmt,
    SymbolTable,
    SymbolTableNode,
    TypeInfo,
    TypeVarExpr,
)
from mypy.types import (
    AnyType,
    CallableType,
    ErasedType,
    Instance,
    NoneType,
    TypeOfAny,
    TypeVarId,
    TypeVarType,
    UnionType,
)

from fastapi_endpoint_detector.analyzer.live_expression_types import (
    ExpressionSnapshotError,
    ExpressionSnapshotLimits,
    live_expression_type_snapshot,
)


def _name() -> NameExpr:
    expr = NameExpr("value")
    expr.set_line(2, column=3, end_line=2, end_column=8)
    return expr


def _tree(*expressions: Expression) -> MypyFile:
    tree = MypyFile([ExpressionStmt(expr) for expr in expressions], [], False)
    tree._fullname = "fixture"
    tree.names = SymbolTable()
    return tree


def _states(tree: MypyFile | None) -> dict[str, SimpleNamespace]:
    return {"fixture": SimpleNamespace(tree=tree)}


def _typevar(name: str = "T", owner: str = "fixture") -> TypeVarExpr:
    return TypeVarExpr(
        name,
        owner + "." + name,
        [],
        AnyType(TypeOfAny.special_form),
        AnyType(TypeOfAny.from_omitted_generics),
    )


def test_stale_map_keys_do_not_change_current_expression_snapshot() -> None:
    expr, stale = _name(), _name()
    tree = _tree(expr)
    types = {expr: NoneType()}
    expected = live_expression_type_snapshot(_states(tree), types)
    types[stale] = AnyType(TypeOfAny.explicit)
    assert len(types) == 2
    assert live_expression_type_snapshot(_states(tree), types) == expected
    assert len(types) == 2  # The projection never rewrites the raw retained map.
    assert expected[0].expressions == expected[0].mapped_expressions == 1


def test_noncall_expression_type_changes_are_detected() -> None:
    expr = _name()
    states = _states(_tree(expr))
    assert live_expression_type_snapshot(states, {expr: NoneType()}) != (
        live_expression_type_snapshot(states, {expr: AnyType(TypeOfAny.explicit)})
    )


def test_missing_current_type_has_an_explicit_marker() -> None:
    expr = _name()
    states = _states(_tree(expr))
    mapped = live_expression_type_snapshot(states, {expr: NoneType()})
    missing = live_expression_type_snapshot(states, {})
    assert mapped != missing
    assert missing[0].expressions == 1
    assert missing[0].mapped_expressions == 0


def test_independent_nodes_have_the_same_stable_type_projection() -> None:
    first, second = _name(), _name()
    assert live_expression_type_snapshot(_states(_tree(first)), {first: NoneType()}) == (
        live_expression_type_snapshot(_states(_tree(second)), {second: NoneType()})
    )


def test_shared_node_is_counted_once_without_following_symbol_backrefs() -> None:
    expr, hidden = _name(), _name()
    expr.node = FuncDef("foreign", [], Block([ReturnStmt(hidden)]))
    snapshot = live_expression_type_snapshot(
        _states(_tree(expr, expr)), {expr: NoneType(), hidden: AnyType(TypeOfAny.explicit)}
    )
    assert snapshot[0].expressions == snapshot[0].mapped_expressions == 1


def test_analyzed_expansion_is_outside_source_expression_scope() -> None:
    callee, synthetic = _name(), _name()
    call = CallExpr(callee, [], [], [])
    call.analyzed = synthetic
    snapshot = live_expression_type_snapshot(
        _states(_tree(call)), {call: NoneType(), callee: NoneType(), synthetic: NoneType()}
    )
    assert snapshot[0].expressions == snapshot[0].mapped_expressions == 2


def test_only_exact_owned_typevar_symbols_are_added() -> None:
    tree = _tree()
    owned, foreign = _typevar(), _typevar("U", "other")
    tree.names["T"] = SymbolTableNode(GDEF, owned)
    tree.names["alias"] = SymbolTableNode(GDEF, owned)
    tree.names["U"] = SymbolTableNode(GDEF, foreign)
    snapshot = live_expression_type_snapshot(
        _states(tree), {owned: NoneType(), foreign: NoneType()}
    )
    assert snapshot[0].owned_typevars == 1
    assert snapshot[0].expressions == snapshot[0].mapped_expressions == 1


def test_typevar_bound_is_evidence_even_without_a_map_entry() -> None:
    tree = _tree()
    declaration = _typevar()
    tree.names["T"] = SymbolTableNode(GDEF, declaration)
    before = live_expression_type_snapshot(_states(tree), {})
    declaration.upper_bound = NoneType()
    after = live_expression_type_snapshot(_states(tree), {})
    assert before != after
    assert after[0].owned_typevars == 1
    assert after[0].mapped_expressions == 0


def test_typevar_serialized_allocator_ids_are_not_silently_normalized() -> None:
    expr = _name()
    states = _states(_tree(expr))
    first = TypeVarType(
        "T",
        "fixture.T",
        TypeVarId(-1, namespace="fixture.f"),
        [],
        AnyType(TypeOfAny.special_form),
        AnyType(TypeOfAny.from_omitted_generics),
    )
    second = first.copy_modified(id=TypeVarId(-2, namespace="fixture.f"))
    assert live_expression_type_snapshot(states, {expr: first}) != (
        live_expression_type_snapshot(states, {expr: second})
    )


def test_meta_typevar_serialization_is_rejected() -> None:
    expr = _name()
    meta = TypeVarType(
        "T",
        "fixture.T",
        TypeVarId(1, meta_level=1),
        [],
        AnyType(TypeOfAny.special_form),
        AnyType(TypeOfAny.from_omitted_generics),
    )
    with pytest.raises(ExpressionSnapshotError, match="cannot be serialized"):
        live_expression_type_snapshot(_states(_tree(expr)), {expr: meta})


def test_unsupported_type_fails_instead_of_becoming_missing() -> None:
    expr = _name()
    with pytest.raises(ExpressionSnapshotError, match="unsupported expression type"):
        live_expression_type_snapshot(_states(_tree(expr)), {expr: ErasedType()})


def test_cyclic_current_syntax_is_rejected() -> None:
    expr = ListExpr([])
    expr.items.append(expr)
    with pytest.raises(ExpressionSnapshotError, match="cyclic current syntax"):
        live_expression_type_snapshot(_states(_tree(expr)), {})


def test_cyclic_serialized_type_graph_is_rejected_before_serialize() -> None:
    expr = _name()
    typ = UnionType([NoneType()])
    typ.items.append(typ)
    with pytest.raises(ExpressionSnapshotError, match="cyclic expression type"):
        live_expression_type_snapshot(_states(_tree(expr)), {expr: typ})


@pytest.mark.parametrize(
    ("limit", "value", "message"),
    [
        ("nodes_per_module", 1, "node limit"),
        ("total_nodes", 1, "node limit"),
        ("work_items", 1, "work-item|pending-work"),
        ("syntax_depth", 1, "syntax-depth"),
        ("encoded_bytes", 1, "encoded-byte"),
        ("json_items", 1, "JSON traversal"),
        ("string_chars", 1, "JSON string"),
    ],
)
def test_snapshot_limits_never_return_partial_success(limit: str, value: int, message: str) -> None:
    expr = _name()
    limits = ExpressionSnapshotLimits(**{limit: value})
    with pytest.raises(ExpressionSnapshotError, match=message):
        live_expression_type_snapshot(_states(_tree(expr)), {expr: NoneType()}, limits=limits)


def test_expression_count_limit_is_separate_from_node_limit() -> None:
    first, second = _name(), _name()
    with pytest.raises(ExpressionSnapshotError, match="expression limit"):
        live_expression_type_snapshot(
            _states(_tree(first, second)),
            {},
            limits=ExpressionSnapshotLimits(expressions=1),
        )


def test_container_limit_applies_before_enumeration() -> None:
    expr = ListExpr([_name(), _name()])
    with pytest.raises(ExpressionSnapshotError, match="container-item"):
        live_expression_type_snapshot(
            _states(_tree(expr)), {}, limits=ExpressionSnapshotLimits(container_items=1)
        )


def test_type_depth_limit_applies_before_serialize() -> None:
    expr = _name()
    typ = UnionType([UnionType([NoneType()])])
    with pytest.raises(ExpressionSnapshotError, match="type traversal"):
        live_expression_type_snapshot(
            _states(_tree(expr)), {expr: typ}, limits=ExpressionSnapshotLimits(type_depth=1)
        )


def test_missing_module_tree_differs_from_an_empty_tree() -> None:
    assert live_expression_type_snapshot(_states(None), {}) != (
        live_expression_type_snapshot(_states(_tree()), {})
    )


def test_module_order_does_not_change_snapshot() -> None:
    tree = _tree()
    states = {"second": SimpleNamespace(tree=tree), "first": SimpleNamespace(tree=tree)}
    assert live_expression_type_snapshot(states, {}) == (
        live_expression_type_snapshot(dict(reversed(list(states.items()))), {})
    )


@pytest.mark.parametrize("value", [True, 0, -1, 1.0])
def test_invalid_limit_types_and_values_are_rejected(value: object) -> None:
    with pytest.raises(ExpressionSnapshotError, match="invalid snapshot limit"):
        ExpressionSnapshotLimits(work_items=value)  # type: ignore[arg-type]


def test_template_string_children_use_only_source_expression_edges() -> None:
    cls = getattr(mypy_nodes, "TemplateStrExpr", None)
    if cls is None:
        pytest.skip("TemplateStrExpr exists in the Mypy 2.4 profile")
    value, format_spec = _name(), _name()
    literal = mypy_nodes.StrExpr("literal")
    expr = cls([literal, (value, "value", None, format_spec)])
    snapshot = live_expression_type_snapshot(
        _states(_tree(expr)),
        {expr: NoneType(), value: NoneType(), literal: NoneType(), format_spec: NoneType()},
    )
    assert snapshot[0].expressions == snapshot[0].mapped_expressions == 4


@pytest.mark.parametrize(
    "interpolation",
    [(_name(), "value"), (_name(), 1, None, None), (_name(), "value", None, "not-an-expression")],
)
def test_malformed_template_string_interpolation_is_rejected(interpolation: tuple) -> None:
    cls = getattr(mypy_nodes, "TemplateStrExpr", None)
    if cls is None:
        pytest.skip("TemplateStrExpr exists in the Mypy 2.4 profile")
    expr = cls([interpolation])
    with pytest.raises(ExpressionSnapshotError, match="template-string interpolation"):
        live_expression_type_snapshot(_states(_tree(expr)), {})


def test_callable_instance_type_cycle_is_preflighted() -> None:
    cls = ClassDef("function", Block([]))
    info = TypeInfo(SymbolTable(), cls, "builtins")
    info._fullname = "builtins.function"
    fallback = Instance(info, [])
    callable_type = CallableType([], [], [], NoneType(), fallback)
    if not hasattr(callable_type, "instance_type"):
        pytest.skip("CallableType.instance_type exists in the Mypy 2.4 profile")
    cyclic = Instance(info, [])
    cyclic.args = (callable_type,)
    callable_type.instance_type = cyclic
    expr = _name()
    with pytest.raises(ExpressionSnapshotError, match="cyclic expression type"):
        live_expression_type_snapshot(_states(_tree(expr)), {expr: callable_type})
