"""Boundary tests for the private bounded static string evaluator."""

import ast

from fastapi_endpoint_detector.parser._static_evaluation import (
    MAX_CUSTOM_RESOURCE_CHARS,
    MAX_STATIC_DEPTH,
    MAX_STATIC_STEPS,
    MAX_STATIC_STRING_CHARS,
    MAX_STATIC_TOTAL_CHARS,
    MAX_STATIC_VALUES,
    StaticStringEvaluator,
)


def _nested_tuple(depth: int) -> ast.expr:
    expression: ast.expr = ast.Constant(value="x")
    for _ in range(depth):
        expression = ast.Tuple(elts=[expression], ctx=ast.Load())
    return expression


def test_static_depth_boundary_is_deterministic_without_recursion_error() -> None:
    exact = StaticStringEvaluator().evaluate_values(_nested_tuple(MAX_STATIC_DEPTH - 1))
    exceeded = StaticStringEvaluator().evaluate_values(_nested_tuple(MAX_STATIC_DEPTH))

    assert exact.values == ("x",)
    assert exceeded.values is None
    assert exceeded.failure == "depth"


def test_static_step_boundary_and_limit_plus_one() -> None:
    # JoinedStr itself and each literal part consume one AST step.
    exact_expression = ast.JoinedStr(
        values=[ast.Constant(value="") for _ in range(MAX_STATIC_STEPS - 1)]
    )
    exceeded_expression = ast.JoinedStr(
        values=[ast.Constant(value="") for _ in range(MAX_STATIC_STEPS)]
    )

    assert StaticStringEvaluator().evaluate_string(exact_expression).string == ""
    exceeded = StaticStringEvaluator().evaluate_string(exceeded_expression)
    assert exceeded.values is None
    assert exceeded.failure == "steps"


def test_static_string_boundary_and_exponential_preflight() -> None:
    assert (
        StaticStringEvaluator()
        .evaluate_string(ast.Constant(value="x" * MAX_STATIC_STRING_CHARS))
        .string
        == "x" * MAX_STATIC_STRING_CHARS
    )
    exceeded = StaticStringEvaluator().evaluate_string(
        ast.Constant(value="x" * (MAX_STATIC_STRING_CHARS + 1))
    )
    assert exceeded.failure == "string"

    doubling = ast.BinOp(
        left=ast.Name(id="value", ctx=ast.Load()),
        op=ast.Add(),
        right=ast.Name(id="value", ctx=ast.Load()),
    )
    amplified = StaticStringEvaluator(
        resolve_name=lambda _name: "x" * MAX_STATIC_STRING_CHARS
    ).evaluate_string(doubling)
    assert amplified.values is None
    assert amplified.failure in {"string", "aggregate"}


def test_static_aggregate_character_boundary_preflights_concatenation() -> None:
    half = MAX_STATIC_TOTAL_CHARS // 4
    exact = ast.BinOp(
        left=ast.Constant(value="x" * half),
        op=ast.Add(),
        right=ast.Constant(value="x" * half),
    )
    exceeded = ast.BinOp(
        left=ast.Constant(value="x" * (half + 1)),
        op=ast.Add(),
        right=ast.Constant(value="x" * half),
    )
    evaluator_options = {
        "max_string_chars": MAX_STATIC_TOTAL_CHARS,
        "max_total_chars": MAX_STATIC_TOTAL_CHARS,
    }

    assert StaticStringEvaluator(**evaluator_options).evaluate_string(exact).string == (
        "x" * (half * 2)
    )
    result = StaticStringEvaluator(**evaluator_options).evaluate_string(exceeded)
    assert result.values is None
    assert result.failure == "aggregate"


def test_raw_duplicate_values_share_the_output_cap() -> None:
    exact = ast.List(
        elts=[ast.Constant(value="GET") for _ in range(MAX_STATIC_VALUES)],
        ctx=ast.Load(),
    )
    exceeded = ast.List(
        elts=[ast.Constant(value="GET") for _ in range(MAX_STATIC_VALUES + 1)],
        ctx=ast.Load(),
    )

    assert len(StaticStringEvaluator().evaluate_values(exact).values or ()) == MAX_STATIC_VALUES
    result = StaticStringEvaluator().evaluate_values(exceeded)
    assert result.values is None
    assert result.failure == "values"


def test_custom_resource_string_boundary() -> None:
    assert StaticStringEvaluator(max_string_chars=MAX_CUSTOM_RESOURCE_CHARS).evaluate_values(
        ast.Constant(value="x" * MAX_CUSTOM_RESOURCE_CHARS)
    ).values == ("x" * MAX_CUSTOM_RESOURCE_CHARS,)
    result = StaticStringEvaluator(max_string_chars=MAX_CUSTOM_RESOURCE_CHARS).evaluate_values(
        ast.Constant(value="x" * (MAX_CUSTOM_RESOURCE_CHARS + 1))
    )
    assert result.values is None
    assert result.failure == "string"


def test_hard_failure_is_terminal_even_for_a_later_empty_aggregate() -> None:
    evaluator = StaticStringEvaluator(max_values=1)
    failed = evaluator.evaluate_values(
        ast.Tuple(
            elts=[ast.Constant(value="first"), ast.Constant(value="second")],
            ctx=ast.Load(),
        )
    )

    later = evaluator.evaluate_values(ast.Tuple(elts=[], ctx=ast.Load()))

    assert failed.failure == "values"
    assert later.values is None
    assert later.failure == "values"


def test_unsupported_failure_is_terminal_for_later_valid_evaluations() -> None:
    evaluator = StaticStringEvaluator()
    failed = evaluator.evaluate_string(
        ast.Call(func=ast.Name(id="dynamic", ctx=ast.Load()), args=[], keywords=[])
    )

    later_string = evaluator.evaluate_string(ast.Constant(value="valid"))
    later_values = evaluator.evaluate_flat_values(
        ast.List(elts=[ast.Constant(value="GET")], ctx=ast.Load())
    )

    assert failed.failure == "unsupported"
    assert later_string.failure == "unsupported"
    assert later_values.failure == "unsupported"
