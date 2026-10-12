"""Own in-memory node controls; no parsed app or provider build is needed."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

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
    ExtraAttrs,
    Instance,
    NoneType,
    Type,
    TypeOfAny,
    TypeVarId,
    TypeVarType,
    UnionType,
)

from fastapi_endpoint_detector.analyzer.live_expression_types import (
    ExpressionSnapshotError,
    ExpressionSnapshotLimits,
    _Budget,
    _extra_attrs_children,
    _serialize_type,
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
    types: dict[Expression, Type] = {expr: NoneType()}
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
def test_malformed_template_string_interpolation_is_rejected(
    interpolation: tuple[Any, ...],
) -> None:
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


def _module_type(extra: ExtraAttrs | None = None) -> Instance:
    cls = ClassDef("ModuleType", Block([]))
    info = TypeInfo(SymbolTable(), cls, "types")
    info._fullname = "types.ModuleType"
    result = Instance(info, [])
    result.extra_attrs = extra
    return result


def _module_snapshot(
    extra: ExtraAttrs | None, *, limits: ExpressionSnapshotLimits | None = None
) -> object:
    expr = _name()
    return live_expression_type_snapshot(
        _states(_tree(expr)), {expr: _module_type(extra)}, limits=limits
    )


def test_module_extra_attrs_are_serialized_without_mutating_the_retained_type() -> None:
    expr = _name()
    extra = ExtraAttrs({"answer": NoneType()}, {"answer"}, "fixture.module")
    typ = _module_type(extra)
    retained: dict[Expression, Type] = {expr: typ}
    snapshot = live_expression_type_snapshot(_states(_tree(expr)), retained)
    assert snapshot[0].expressions == snapshot[0].mapped_expressions == 1
    assert retained[expr] is typ and typ.extra_attrs is extra
    assert extra.immutable == {"answer"} and extra.mod_name == "fixture.module"
    assert _module_snapshot(None) != _module_snapshot(ExtraAttrs({}, set(), None))
    assert _module_snapshot(extra) == _module_snapshot(
        ExtraAttrs({"answer": NoneType()}, {"answer"}, "fixture.module")
    )


def test_module_extra_attrs_insertion_order_is_not_type_evidence() -> None:
    names = ("answer", "message", "status", "version")
    first = ExtraAttrs({name: NoneType() for name in names}, set(names), "fixture.module")
    second_immutable: set[str] = set()
    for name in reversed(names):
        second_immutable.add(name)
    second = ExtraAttrs(
        {name: NoneType() for name in reversed(names)}, second_immutable, "fixture.module"
    )
    assert _module_snapshot(first) == _module_snapshot(second)


@pytest.mark.parametrize(
    "changed",
    [
        ExtraAttrs({"changed": NoneType()}, {"answer"}, "fixture.module"),
        ExtraAttrs({"answer": AnyType(TypeOfAny.explicit)}, {"answer"}, "fixture.module"),
        ExtraAttrs({"answer": NoneType()}, set(), "fixture.module"),
        ExtraAttrs({"answer": NoneType()}, {"other"}, "fixture.module"),
        ExtraAttrs({"answer": NoneType()}, {"answer"}, "another.module"),
        ExtraAttrs({"answer": NoneType()}, {"answer"}, None),
    ],
)
def test_each_module_extra_attrs_semantic_field_changes_the_digest(changed: ExtraAttrs) -> None:
    original = ExtraAttrs({"answer": NoneType()}, {"answer"}, "fixture.module")
    assert _module_snapshot(original) != _module_snapshot(changed)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attrs", []),
        ("attrs", {1: NoneType()}),
        ("attrs", {"answer": "not-a-Type"}),
        ("immutable", []),
        ("immutable", {1}),
        ("mod_name", True),
    ],
)
def test_malformed_module_extra_attrs_never_produce_a_successful_snapshot(
    field: str, value: Any
) -> None:
    extra = ExtraAttrs({}, set(), None)
    with pytest.raises((TypeError, ExpressionSnapshotError)):
        # Compiled Mypy models may reject malformed fields before the serializer.
        setattr(extra, field, value)
        _module_snapshot(extra)


@pytest.mark.parametrize("field", ["attrs", "immutable", "mod_name"])
def test_module_extra_attrs_string_limits_apply_before_serialize(field: str) -> None:
    extra = ExtraAttrs({}, set(), None)
    if field == "attrs":
        extra.attrs["long_attribute_name"] = NoneType()
    elif field == "immutable":
        extra.immutable.add("long_attribute_name")
    else:
        extra.mod_name = "long_module_name"
    with pytest.raises(ExpressionSnapshotError, match="ExtraAttrs"):
        _serialize_type(_module_type(extra), _Budget(ExpressionSnapshotLimits(string_chars=4)))


@pytest.mark.parametrize("field", ["attrs", "immutable"])
def test_module_extra_attrs_container_limits_apply_before_serialize(field: str) -> None:
    extra = ExtraAttrs({}, set(), None)
    if field == "attrs":
        extra.attrs.update({"first": NoneType(), "second": NoneType()})
    else:
        extra.immutable.update({"first", "second"})
    with pytest.raises(ExpressionSnapshotError, match="oversized ExtraAttrs"):
        _serialize_type(_module_type(extra), _Budget(ExpressionSnapshotLimits(container_items=1)))


def test_module_extra_attrs_self_reference_is_preflighted() -> None:
    expr = _name()
    extra = ExtraAttrs({}, set(), None)
    typ = _module_type(extra)
    extra.attrs["self"] = typ
    with pytest.raises(ExpressionSnapshotError, match="cyclic expression type"):
        live_expression_type_snapshot(_states(_tree(expr)), {expr: typ})


@pytest.mark.parametrize(
    ("limit", "value"), [("type_depth", 1), ("type_items", 3), ("work_items", 5)]
)
def test_module_extra_attrs_nested_types_use_existing_traversal_limits(
    limit: str, value: int
) -> None:
    limits = ExpressionSnapshotLimits(**{limit: value})
    _serialize_type(_module_type(None), _Budget(limits))
    extra = ExtraAttrs({"nested": UnionType([UnionType([NoneType()])])}, set(), None)
    with pytest.raises(ExpressionSnapshotError, match="limit"):
        _serialize_type(_module_type(extra), _Budget(limits))


def test_unknown_extra_attrs_shape_is_rejected_by_the_type_preflight() -> None:
    with pytest.raises(ExpressionSnapshotError, match=r"unsupported Instance\.extra_attrs"):
        _extra_attrs_children(
            SimpleNamespace(attrs={}, immutable=set(), mod_name=None),
            _Budget(ExpressionSnapshotLimits()),
        )
