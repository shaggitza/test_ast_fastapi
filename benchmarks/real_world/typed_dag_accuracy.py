#!/usr/bin/env python3
"""Fail-closed generated typed-DAG accuracy gate; synthetic source is never executed."""

from __future__ import annotations

import argparse
import ast
import contextlib
import difflib
import hashlib
import importlib.metadata
import json
import math
import platform
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from fastapi_endpoint_detector.cli import cli

SCHEMA = "typed-dag-accuracy-v1"
RESULTS = Path(__file__).resolve().parents[1] / "results" / SCHEMA


@dataclass(frozen=True)
class Case:
    case_id: str
    symbol: str
    control: bool = False
    supported: bool = True
    change_kind: str = "replacement"
    source_symbol: str | None = None


# Independent fixture edge specification, with endpoint roots and explicit
# reconvergence. Reachability below consults only this table, never analyzer data.
EDGES = {
    "route_one": (
        "direct_one",
        "lambda_live",
        "awaited_live",
        "literal_false_dead",
        "post_return_dead",
        "deferred_closure_dead",
        "deferred_lambda_dead",
        "unawaited_coroutine_dead",
        "literal_true_live",
        "post_return_live",
        "invoked_closure_live",
        "invoked_lambda_live",
    ),
    "route_two": ("right_live",),
    "direct_one": ("shared_live",),
    "right_live": ("shared_live",),
    "shared_live": ("leaf_alias",),
    "lambda_live": ("leaf_alias",),
    "awaited_live": ("leaf_async",),
    "leaf_async": ("leaf_alias",),
    # The route invokes these wrappers, but no feasible edge reaches the
    # expressions that the corresponding control cases modify.
    "literal_false_dead": (),
    "post_return_dead": (),
    "deferred_closure_dead": (),
    "deferred_lambda_dead": (),
    "unawaited_coroutine_dead": (),
    "literal_true_live": ("leaf_alias",),
    "post_return_live": ("leaf_alias",),
    "invoked_closure_live": ("invoked_closure_inner",),
    "invoked_closure_inner": ("leaf_alias",),
    "invoked_lambda_live": ("invoked_lambda_callable",),
    "invoked_lambda_callable": ("leaf_alias",),
    "unrelated_dead": (),
}
CASES = (
    Case("cross_file_alias_reconvergent_leaf", "leaf_alias"),
    Case("cross_file_direct", "direct_one"),
    Case("shared_helper", "shared_live"),
    Case("live_lambda", "lambda_live"),
    Case("live_awaited_coroutine", "awaited_live"),
    Case(
        "literal_false_control",
        "literal_false_site",
        control=True,
        source_symbol="literal_false_dead",
    ),
    Case("post_return_control", "post_return_site", control=True, source_symbol="post_return_dead"),
    Case(
        "deferred_closure_control",
        "deferred_closure_site",
        control=True,
        source_symbol="deferred_closure_dead",
    ),
    Case(
        "deferred_lambda_control",
        "deferred_lambda_site",
        control=True,
        source_symbol="deferred_lambda_dead",
    ),
    Case(
        "unawaited_coroutine_control",
        "unawaited_coroutine_site",
        control=True,
        source_symbol="unawaited_coroutine_dead",
    ),
    Case("unrelated_disconnected_control", "unrelated_dead", control=True),
    Case("live_literal_true_counterpart", "literal_true_live"),
    Case("live_post_return_counterpart", "post_return_live"),
    Case("live_invoked_closure_counterpart", "invoked_closure_live"),
    Case("live_invoked_lambda_counterpart", "invoked_lambda_live"),
    Case("addition_unsupported", "added", supported=False, change_kind="addition"),
    Case("deletion_unsupported", "deleted", supported=False, change_kind="deletion"),
    Case("rename_unsupported", "renamed", supported=False, change_kind="rename"),
)
ROOTS = {"route_one": "GET /one", "route_two": "GET /two"}


def oracle(symbol: str) -> tuple[str, ...]:
    reverse: dict[str, set[str]] = {}
    for caller, callees in EDGES.items():
        for callee in callees:
            reverse.setdefault(callee, set()).add(caller)
    pending, seen, found = [symbol], set(), set()
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        if node in ROOTS:
            found.add(ROOTS[node])
        pending.extend(reverse.get(node, ()))
    return tuple(sorted(found))


def expected_for(case: Case) -> tuple[str, ...]:
    """Resolve each case's expected endpoints exclusively from the edge oracle."""
    return oracle(case.symbol)


def sha(data: str) -> str:
    return "sha256:" + hashlib.sha256(data.encode()).hexdigest()


def sources(symbol: str, replacement: str) -> dict[str, str]:
    helper = "from __future__ import annotations\ndef leaf_alias() -> int:\n    return 1\n"
    if symbol == "leaf_alias":
        helper = (
            f"from __future__ import annotations\ndef leaf_alias() -> int:\n    {replacement}\n"
        )
    body_tokens = {
        "direct_one": "BODY_DIRECT",
        "right_live": "BODY_RIGHT",
        "shared_live": "BODY_SHARED",
        "lambda_live": "BODY_LAMBDA",
        "awaited_live": "BODY_AWAITED",
        "literal_false_dead": "BODY_LITERAL",
        "post_return_dead": "BODY_POSTRETURN",
        "deferred_closure_dead": "BODY_CLOSURE",
        "deferred_lambda_dead": "BODY_DEFERRED_LAMBDA",
        "unawaited_coroutine_dead": "BODY_COROUTINE",
        "unrelated_dead": "BODY_UNRELATED",
        "literal_true_live": "BODY_LITERAL_TRUE",
        "post_return_live": "BODY_POSTRETURN_LIVE",
        "invoked_closure_live": "BODY_CLOSURE_LIVE",
        "invoked_lambda_live": "BODY_LAMBDA_LIVE",
    }
    service = """from __future__ import annotations
from .helpers import leaf_alias as leaf_alias
def direct_one() -> int:
    BODY_DIRECT
def right_live() -> int:
    BODY_RIGHT
def shared_live() -> int:
    BODY_SHARED
def lambda_live() -> int:
    BODY_LAMBDA
async def awaited_live() -> int:
    BODY_AWAITED
async def leaf_async() -> int:
    return leaf_alias()
def literal_false_dead() -> int:
    if False:
        BODY_LITERAL
    return 0
def post_return_dead() -> int:
    return 0
    BODY_POSTRETURN
def deferred_closure_dead() -> int:
    def hidden() -> int:
        BODY_CLOSURE
    return 0
def deferred_lambda_dead() -> int:
    hidden = lambda: BODY_DEFERRED_LAMBDA
    return 0
async def unawaited_coroutine_dead() -> int:
    BODY_COROUTINE
def unrelated_dead() -> int:
    BODY_UNRELATED
def literal_true_live() -> int:
    if True:
        BODY_LITERAL_TRUE
    return 0
def post_return_live() -> int:
    BODY_POSTRETURN_LIVE
    return 0
def invoked_closure_live() -> int:
    def invoked_closure_inner() -> int:
        BODY_CLOSURE_LIVE
    return invoked_closure_inner()
def invoked_lambda_live() -> int:
    live = lambda: BODY_LAMBDA_LIVE
    return live()
"""
    bodies = {
        "direct_one": "return shared_live()",
        "right_live": "return shared_live()",
        "shared_live": "return leaf_alias()",
        "lambda_live": "return (lambda: leaf_alias())()",
        "awaited_live": "return await leaf_async()",
        "literal_false_dead": "return leaf_alias()",
        "post_return_dead": "return leaf_alias()",
        "deferred_closure_dead": "return leaf_alias()",
        "deferred_lambda_dead": "leaf_alias()",
        "unawaited_coroutine_dead": "return leaf_alias()",
        "unrelated_dead": "return 30",
        "literal_true_live": "return leaf_alias()",
        "post_return_live": "return leaf_alias()",
        "invoked_closure_live": "return leaf_alias()",
        "invoked_lambda_live": "leaf_alias()",
    }
    if symbol in body_tokens:
        bodies[symbol] = replacement
    for name, token in sorted(body_tokens.items(), key=lambda item: len(item[1]), reverse=True):
        service = service.replace(token, bodies[name])
    route = """from fastapi import FastAPI
from .service import direct_one, right_live, lambda_live, awaited_live, unawaited_coroutine_dead
from .service import literal_false_dead, post_return_dead
from .service import deferred_closure_dead, deferred_lambda_dead
from .service import literal_true_live, post_return_live, invoked_closure_live, invoked_lambda_live
app = FastAPI()
@app.get("/one")
async def route_one() -> int:
    literal_false_dead()
    post_return_dead()
    deferred_closure_dead()
    deferred_lambda_dead()
    unawaited_coroutine_dead()
    literal_true_live()
    post_return_live()
    invoked_closure_live()
    invoked_lambda_live()
    return direct_one() + lambda_live() + await awaited_live()
@app.get("/two")
def route_two() -> int:
    return right_live()
"""
    return {
        "app/__init__.py": "",
        "app/helpers.py": helper,
        "app/service.py": service,
        "app/routes.py": route,
    }


def make_diff(path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def case_inputs(case: Case) -> dict[str, str]:
    """Regenerate exact paired snapshots, diff, and analyzer configuration."""
    source_symbol = case.source_symbol or case.symbol
    original = sources(source_symbol, "return 1")
    replacements = {
        "leaf_alias": "return 2",
        "direct_one": "return shared_live() + 1",
        "shared_live": "return leaf_alias() + 1",
        "lambda_live": "return (lambda: leaf_alias() + 1)()",
        "awaited_live": "return (await leaf_async()) + 1",
        "literal_false_dead": "return leaf_alias() + 1",
        "post_return_dead": "return leaf_alias() + 1",
        "deferred_closure_dead": "return leaf_alias() + 1",
        "deferred_lambda_dead": "leaf_alias() + 1",
        "unawaited_coroutine_dead": "return leaf_alias() + 1",
        "unrelated_dead": "return 31",
        "literal_true_live": "return leaf_alias() + 1",
        "post_return_live": "return leaf_alias() + 1",
        "invoked_closure_live": "return leaf_alias() + 1",
        "invoked_lambda_live": "leaf_alias() + 1",
    }
    replacement = replacements.get(source_symbol, "return 2")
    modified = sources(source_symbol, replacement)
    changed_path = "app/helpers.py" if source_symbol == "leaf_alias" else "app/service.py"
    if case.change_kind == "addition":
        changed_path = "app/added.py"
        original.pop(changed_path, None)
        modified[changed_path] = "def added() -> int:\n    return 1\n"
        patch = "".join(
            difflib.unified_diff(
                [],
                modified[changed_path].splitlines(keepends=True),
                fromfile="/dev/null",
                tofile=f"b/{changed_path}",
            )
        )
    elif case.change_kind == "deletion":
        changed_path = "app/deleted.py"
        original[changed_path] = "def deleted() -> int:\n    return 1\n"
        modified.pop(changed_path, None)
        patch = "".join(
            difflib.unified_diff(
                original[changed_path].splitlines(keepends=True),
                [],
                fromfile=f"a/{changed_path}",
                tofile="/dev/null",
            )
        )
    elif case.change_kind == "rename":
        changed_path = "app/renamed.py"
        original[changed_path] = "def old_name() -> int:\n    return 1\n"
        modified[changed_path] = "def new_name() -> int:\n    return 1\n"
        patch = make_diff(changed_path, original[changed_path], modified[changed_path])
    else:
        patch = make_diff(changed_path, original[changed_path], modified[changed_path])
    return {
        "baseline": json.dumps(original, sort_keys=True),
        "target": json.dumps(modified, sort_keys=True),
        "diff": patch,
        "config": json.dumps(
            {"secure_ast": True, "backend": "mypy", "transitive": True, "cache": False},
            sort_keys=True,
        ),
    }


def validate_generated_fixture(case: Case, material: dict[str, str]) -> None:  # noqa: PLR0912, PLR0915
    """Bind case metadata and oracle nodes to the deterministic source fixtures."""
    if material != case_inputs(case):
        raise ValueError(f"source/diff/config do not match generator: {case.case_id}")
    target = json.loads(material["target"])
    service_tree = ast.parse(target["app/service.py"])
    routes_tree = ast.parse(target["app/routes.py"])
    functions = {
        item.name: item
        for item in ast.walk(service_tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    route_one = next(
        item
        for item in routes_tree.body
        if isinstance(item, ast.AsyncFunctionDef) and item.name == "route_one"
    )
    route_calls = {
        item.func.id
        for item in ast.walk(route_one)
        if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
    }
    required_wrappers = {
        "literal_false_dead",
        "post_return_dead",
        "deferred_closure_dead",
        "deferred_lambda_dead",
        "unawaited_coroutine_dead",
        "literal_true_live",
        "post_return_live",
        "invoked_closure_live",
        "invoked_lambda_live",
    }
    if not required_wrappers <= route_calls or "unrelated_dead" in route_calls:
        raise ValueError(
            "negative controls are not endpoint-reachable or unrelated control is "
            f"connected: {case.case_id}"
        )
    # Assert that source call edges for ordinary live calls match EDGE_SPEC.
    source_callers = {
        "direct_one": {"shared_live"},
        "right_live": {"shared_live"},
        "shared_live": {"leaf_alias"},
        "lambda_live": {"leaf_alias"},
        "awaited_live": {"leaf_async"},
        "leaf_async": {"leaf_alias"},
        "literal_true_live": {"leaf_alias"},
        "post_return_live": {"leaf_alias"},
        "invoked_closure_live": {"invoked_closure_inner"},
        "invoked_closure_inner": {"leaf_alias"},
    }
    for caller, expected_callees in source_callers.items():
        node = functions.get(caller)
        if node is None:
            raise ValueError(f"missing generated callable: {caller}")
        names = {
            item.func.id
            for item in ast.walk(node)
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
        }
        if not expected_callees <= names:
            raise ValueError(f"generator edge is absent from source: {caller}")
    lambda_function = functions.get("invoked_lambda_live")
    if lambda_function is None:
        raise ValueError("missing live lambda counterpart")
    lambda_nodes = [item for item in ast.walk(lambda_function) if isinstance(item, ast.Lambda)]
    if (
        not lambda_nodes
        or not any(isinstance(item, ast.Call) for item in ast.walk(lambda_nodes[0]))
        or not any(
            isinstance(item, ast.Call)
            and isinstance(item.func, ast.Name)
            and item.func.id == "live"
            for item in ast.walk(lambda_function)
        )
    ):
        raise ValueError("live lambda counterpart is not invoked")
    if (
        oracle("literal_false_site")
        or oracle("post_return_site")
        or oracle("deferred_closure_site")
        or oracle("deferred_lambda_site")
        or oracle("unawaited_coroutine_site")
    ):
        raise ValueError("dead/deferred fixture sites must remain unreachable in the edge oracle")
    # Cases change the inner expression, while route_one calls the wrapper.
    source_symbol = case.source_symbol
    if source_symbol == "literal_false_dead":
        node = functions[source_symbol]
        branches = [
            item
            for item in ast.walk(node)
            if isinstance(item, ast.If)
            and isinstance(item.test, ast.Constant)
            and item.test.value is False
        ]
        if not branches or not any(isinstance(item, ast.Call) for item in ast.walk(branches[0])):
            raise ValueError("literal-false control is not a changed unreachable call")
    elif source_symbol == "post_return_dead":
        node = functions[source_symbol]
        first_return = next(
            (i for i, item in enumerate(node.body) if isinstance(item, ast.Return)), None
        )
        if first_return is None or not any(
            isinstance(item, ast.Call)
            for stmt in node.body[first_return + 1 :]
            for item in ast.walk(stmt)
        ):
            raise ValueError("post-return control is not after a return")
    elif source_symbol == "deferred_closure_dead":
        node = functions[source_symbol]
        nested = [
            item
            for item in ast.walk(node)
            if isinstance(item, ast.FunctionDef) and item.name == "hidden"
        ]
        if (
            not nested
            or not any(isinstance(item, ast.Call) for item in ast.walk(nested[0]))
            or "hidden" in route_calls
        ):
            raise ValueError("deferred closure is not uncalled")
    elif source_symbol == "deferred_lambda_dead":
        node = functions[source_symbol]
        lambdas = [item for item in ast.walk(node) if isinstance(item, ast.Lambda)]
        if not lambdas or not any(isinstance(item, ast.Call) for item in ast.walk(lambdas[0])):
            raise ValueError("deferred lambda control has no inner call")
    elif source_symbol == "unawaited_coroutine_dead":
        node = functions[source_symbol]
        route_call = next(
            (
                item
                for item in ast.walk(route_one)
                if isinstance(item, ast.Call)
                and isinstance(item.func, ast.Name)
                and item.func.id == source_symbol
            ),
            None,
        )
        if (
            not isinstance(node, ast.AsyncFunctionDef)
            or route_call is None
            or any(
                isinstance(parent, ast.Await) and route_call in ast.walk(parent)
                for parent in ast.walk(route_one)
            )
        ):
            raise ValueError("unawaited coroutine control is not an unawaited call")


def _metric(case: dict[str, Any]) -> None:
    expected = set(case["expected"])
    predicted = {row["endpoint"] for row in case["actual"]}
    tp, fp, fn = len(expected & predicted), len(predicted - expected), len(expected - predicted)
    precision = tp / (tp + fp) if tp + fp else (1.0 if not expected else 0.0)
    recall = tp / (tp + fn) if tp + fn else 1.0
    if (tp, fp, fn, precision, recall) != (
        case["tp"],
        case["fp"],
        case["fn"],
        case["precision"],
        case["recall"],
    ):
        raise ValueError(f"inconsistent metrics in {case['case_id']}")


def _actual_from_report(report: dict[str, Any]) -> list[dict[str, str]]:
    actual = []
    for candidate in report.get("candidate_endpoints", []):
        endpoint = candidate["endpoint"]
        method = endpoint.get("method", "GET")
        actual.append(
            {
                "endpoint": f"{method} {endpoint.get('path', '')}",
                "confidence": str(candidate["confidence"]).lower().split(".")[-1],
            }
        )
    return sorted(actual, key=lambda row: (row["endpoint"], row["confidence"]))


def _validate_case_record(  # noqa: PLR0912, PLR0915
    record: dict[str, Any], declared: Case
) -> None:
    case_id = declared.case_id
    expected_metadata = {
        "symbol": declared.symbol,
        "source_symbol": declared.source_symbol,
        "control": declared.control,
        "supported": declared.supported,
        "change_kind": declared.change_kind,
    }
    if any(record.get(key) != value for key, value in expected_metadata.items()):
        raise ValueError(f"case metadata differs from declared fixture: {case_id}")
    if record.get("expected") != list(oracle(declared.symbol)):
        raise ValueError(f"oracle mismatch: {case_id}")
    material = record.get("input_material")
    hashes = record.get("input_hashes")
    if not isinstance(material, dict) or not isinstance(hashes, dict):
        raise ValueError(f"missing generator input provenance: {case_id}")
    validate_generated_fixture(declared, material)
    if {key: sha(value) for key, value in material.items()} != hashes:
        raise ValueError(f"tampered/missing input hashes: {case_id}")
    if not isinstance(record.get("analyzer_errors"), list) or not isinstance(
        record.get("analyzer_warnings"), list
    ):
        raise ValueError(f"analyzer diagnostics must be explicitly recorded: {case_id}")
    if declared.supported:
        if record.get("source_discovery") != "secure_ast":
            raise ValueError(f"case did not use secure source discovery: {case_id}")
        if record.get("status") not in {"passed", "failed"}:
            raise ValueError(f"supported case is missing or skipped: {case_id}")
        for metric in ("precision", "recall"):
            if not isinstance(record.get(metric), (int, float)) or not math.isfinite(
                record[metric]
            ):
                raise ValueError(f"non-finite {metric}: {case_id}")
        actual_keys = [(row["endpoint"], row["confidence"]) for row in record.get("actual", [])]
        if len(actual_keys) != len(set(actual_keys)):
            raise ValueError(f"duplicate candidates: {case_id}")
        if any(row["confidence"] not in {"high", "medium", "low"} for row in record["actual"]):
            raise ValueError(f"invalid confidence tier: {case_id}")
        _metric(record)
        evidence = record.get("cli_evidence")
        if evidence is None:
            if record["status"] == "passed":
                raise ValueError(f"passing case lacks real CLI evidence: {case_id}")
            if not record.get("analyzer_errors"):
                raise ValueError(f"failed case lacks CLI evidence or explicit error: {case_id}")
            return
        report = evidence.get("report")
        if (
            evidence.get("interface") != "fastapi-endpoint-detector analyze"
            or evidence.get("exit_code") != 0
            or evidence.get("options") != ["--secure-ast", "--no-cache", "--format", "json"]
            or not isinstance(report, dict)
            or evidence.get("report_hash")
            != sha(json.dumps(report, sort_keys=True, separators=(",", ":")))
        ):
            raise ValueError(f"invalid CLI report evidence: {case_id}")
        if _actual_from_report(report) != record["actual"]:
            raise ValueError(f"candidate rows differ from CLI report: {case_id}")
        errors = report.get("errors", [])
        warnings = report.get("warnings", [])
        limitations = report.get("inventory_limitations", [])
        inventory_status = report.get("inventory_status")
        total_endpoints = report.get("summary", {}).get("total_endpoints")
        if record.get("analyzer_errors") != errors or record.get("analyzer_warnings") != warnings:
            raise ValueError(f"diagnostics differ from CLI report: {case_id}")
        if (
            record.get("inventory_status") != inventory_status
            or record.get("total_endpoints") != total_endpoints
        ):
            raise ValueError(f"endpoint inventory differs from CLI report: {case_id}")
        if record.get("inventory_limitations") != limitations:
            raise ValueError(f"inventory limitations differ from CLI report: {case_id}")
        if not isinstance(warnings, list):
            raise ValueError(f"warnings must be explicitly recorded: {case_id}")
        computed_pass = (
            record["precision"] == 1.0
            and record["recall"] == 1.0
            and not errors
            and inventory_status == "established"
            and total_endpoints == len(ROOTS)
            and not limitations
            and not (
                declared.control
                and any(row["confidence"] in {"high", "medium"} for row in record["actual"])
            )
        )
        if record["status"] == "passed" and not computed_pass:
            raise ValueError(f"case claims pass despite errors or incomplete inventory: {case_id}")
    elif record.get("status") not in {"unsupported", "failed"} or "cli_evidence" in record:
        raise ValueError(f"unsupported case cannot satisfy the gate: {case_id}")
    elif record.get("status") == "failed" and not record.get("error"):
        raise ValueError(f"failed unsupported case lacks an explicit error: {case_id}")


def _tier_metrics(
    cases: list[dict[str, Any]], confidences: set[str]
) -> dict[str, int | float | None]:
    counts = dict.fromkeys(("tp", "fp", "fn"), 0)
    for case in cases:
        expected = set(case["expected"])
        predicted = {row["endpoint"] for row in case["actual"] if row["confidence"] in confidences}
        counts["tp"] += len(expected & predicted)
        counts["fp"] += len(predicted - expected)
        counts["fn"] += len(expected - predicted)
    precision_denominator = counts["tp"] + counts["fp"]
    recall_denominator = counts["tp"] + counts["fn"]
    return {
        **counts,
        "precision": counts["tp"] / precision_denominator if precision_denominator else None,
        "recall": counts["tp"] / recall_denominator if recall_denominator else None,
    }


def validate(document: dict[str, Any]) -> None:  # noqa: PLR0912
    if document.get("schema") != SCHEMA:
        raise ValueError("invalid schema")
    runtime = document.get("runtime")
    if not isinstance(runtime, dict) or document.get("dependency_versions") != runtime:
        raise ValueError("missing dependency version provenance")
    if document.get("dependency_version_hash") != sha(json.dumps(runtime, sort_keys=True)):
        raise ValueError("tampered dependency version hash")
    if document.get("tool_revision_hash") != sha(str(document.get("revision", ""))):
        raise ValueError("tampered tool revision hash")
    if document.get("configuration_hash") != sha(
        json.dumps(document.get("configuration"), sort_keys=True)
    ):
        raise ValueError("tampered configuration hash")
    try:
        current_harness_hash = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError as exc:
        raise ValueError("harness source is unavailable for hash verification") from exc
    if document.get("harness_sha256") != current_harness_hash:
        raise ValueError("tampered harness hash")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be non-empty")
    ids = [case.get("case_id") for case in cases]
    if len(ids) != len(set(ids)) or set(ids) != {case.case_id for case in CASES}:
        raise ValueError("duplicate, missing, or undeclared case")
    for record in cases:
        if record.get("status") not in {"passed", "failed", "unsupported"}:
            raise ValueError(f"invalid case status: {record.get('case_id')}")
        declared = next(item for item in CASES if item.case_id == record["case_id"])
        _validate_case_record(record, declared)
    supported = [record for record in cases if record["supported"]]
    expected_coverage = {
        "declared": len(CASES),
        "recorded": len(cases),
        "supported": sum(case.supported for case in CASES),
        "unsupported": sum(not case.supported for case in CASES),
    }
    if document.get("case_coverage") != expected_coverage:
        raise ValueError("case coverage does not match declared suite")
    counts = {key: sum(record[key] for record in supported) for key in ("tp", "fp", "fn")}
    precision_denominator = counts["tp"] + counts["fp"]
    recall_denominator = counts["tp"] + counts["fn"]
    aggregate = {
        **counts,
        "precision": counts["tp"] / precision_denominator
        if precision_denominator
        else (1.0 if not counts["fn"] else 0.0),
        "recall": counts["tp"] / recall_denominator if recall_denominator else 1.0,
        "high_medium_control_candidates": sum(
            row["confidence"] in {"high", "medium"}
            for record in supported
            if record["control"]
            for row in record["actual"]
        ),
        "high_medium": _tier_metrics(supported, {"high", "medium"}),
        "low_report_only": _tier_metrics(supported, {"low"}),
    }
    metrics = document.get("metrics")
    if metrics != aggregate:
        raise ValueError("aggregate metrics do not match validated case rows")
    if any(not math.isfinite(value) for value in _numeric_metrics(aggregate)):
        raise ValueError("non-finite aggregate metric")
    derived_pass = (
        bool(supported)
        and all(record["status"] == "passed" for record in supported)
        and all(record["status"] in {"passed", "unsupported"} for record in cases)
        and aggregate["precision"] == aggregate["recall"] == 1.0
        and aggregate["high_medium_control_candidates"] == 0
    )
    if document.get("gate_status") != ("passed" if derived_pass else "failed"):
        raise ValueError("gate status contradicts validated cases and metrics")


def _numeric_metrics(value: Any) -> list[float]:
    if isinstance(value, dict):
        return [number for nested in value.values() for number in _numeric_metrics(nested)]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [float(value)]
    return []


def execute_case(case: Case, root: Path) -> dict[str, Any]:
    material = case_inputs(case)
    validate_generated_fixture(case, material)
    expected = expected_for(case)
    if not case.supported:
        return {
            "case_id": case.case_id,
            "symbol": case.symbol,
            "source_symbol": case.source_symbol,
            "supported": False,
            "control": case.control,
            "status": "unsupported",
            "change_kind": case.change_kind,
            "limitation": (
                "the shipped mypy mapper has no paired baseline/target symbol mapping "
                "for this change kind"
            ),
            "expected": list(expected),
            "actual": [],
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "precision": None,
            "recall": None,
            "source_discovery": "unsupported",
            "inventory_status": None,
            "inventory_limitations": [],
            "total_endpoints": None,
            "analyzer_errors": [],
            "analyzer_warnings": [],
            "input_material": material,
        }
    target = root / case.case_id / "target"
    target_sources = json.loads(material["target"])
    for rel, text in target_sources.items():
        path = target / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    diff_path = root / f"{case.case_id}.diff"
    diff_path.write_text(material["diff"], encoding="utf-8")
    result = CliRunner().invoke(
        cli,
        [
            "analyze",
            "--app",
            str(target / "app"),
            "--diff",
            str(diff_path),
            "--format",
            "json",
            "--secure-ast",
            "--no-cache",
        ],
    )
    if result.exit_code:
        raise RuntimeError(f"CLI failed ({case.case_id}): {result.output}; {result.exception}")
    report = json.loads(result.output)
    actual = _actual_from_report(report)
    report_material = json.dumps(report, sort_keys=True, separators=(",", ":"))
    cli_evidence = {
        "interface": "fastapi-endpoint-detector analyze",
        "exit_code": result.exit_code,
        "options": ["--secure-ast", "--no-cache", "--format", "json"],
        "report": report,
        "report_hash": sha(report_material),
    }
    predicted = {row["endpoint"] for row in actual}
    expected_endpoints = set(expected)
    tp, fp, fn = (
        len(predicted & expected_endpoints),
        len(predicted - expected_endpoints),
        len(expected_endpoints - predicted),
    )
    precision = tp / (tp + fp) if tp + fp else (1.0 if not expected_endpoints else 0.0)
    recall = tp / (tp + fn) if tp + fn else 1.0
    inventory_status = report.get("inventory_status")
    total_endpoints = report.get("summary", {}).get("total_endpoints")
    diagnostics_clear = (
        not report.get("errors")
        and inventory_status == "established"
        and total_endpoints == len(ROOTS)
    )
    passed = (
        precision == recall == 1.0
        and diagnostics_clear
        and not (case.control and any(row["confidence"] in {"high", "medium"} for row in actual))
    )
    return {
        "case_id": case.case_id,
        "symbol": case.symbol,
        "source_symbol": case.source_symbol,
        "supported": True,
        "control": case.control,
        "status": "passed" if passed else "failed",
        "change_kind": case.change_kind,
        "expected": sorted(expected),
        "actual": actual,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "source_discovery": "secure_ast",
        "inventory_status": report.get("inventory_status"),
        "inventory_limitations": report.get("inventory_limitations", []),
        "total_endpoints": total_endpoints,
        "analyzer_errors": report.get("errors", []),
        "analyzer_warnings": report.get("warnings", []),
        "cli_evidence": cli_evidence,
        "input_material": material,
    }


def run(output: Path) -> dict[str, Any]:
    records = []
    with tempfile.TemporaryDirectory(prefix="typed-dag-accuracy-") as tmp:
        root = Path(tmp)
        for case in CASES:
            try:
                record = execute_case(case, root)
            except Exception as exc:
                expected = list(oracle(case.symbol))
                record = {
                    "case_id": case.case_id,
                    "symbol": case.symbol,
                    "source_symbol": case.source_symbol,
                    "supported": case.supported,
                    "control": case.control,
                    "change_kind": case.change_kind,
                    "status": "failed",
                    "expected": expected,
                    "actual": [],
                    "tp": 0,
                    "fp": 0,
                    "fn": len(expected),
                    "precision": 0.0,
                    "recall": 0.0,
                    "error": str(exc),
                    "analyzer_errors": [str(exc)],
                    "analyzer_warnings": [],
                    "source_discovery": "secure_ast" if case.supported else "unsupported",
                    "inventory_status": None,
                    "inventory_limitations": [],
                    "total_endpoints": None,
                    "input_material": case_inputs(case),
                }
            record["input_hashes"] = {
                key: sha(value) for key, value in record["input_material"].items()
            }
            records.append(record)
    supported = [item for item in records if item["supported"]]
    tp, fp, fn = (sum(item[key] for item in supported) for key in ("tp", "fp", "fn"))
    precision = tp / (tp + fp) if tp + fp else (1.0 if not fn else 0.0)
    recall = tp / (tp + fn) if tp + fn else 1.0
    hm_controls = sum(
        row["confidence"] in {"high", "medium"}
        for item in supported
        if item["control"]
        for row in item["actual"]
    )
    tier_totals: dict[str, dict[str, int]] = {
        tier: dict.fromkeys(("tp", "fp", "fn"), 0) for tier in ("high_medium", "low_report_only")
    }
    for item in supported:
        expected_endpoints = set(item["expected"])
        for tier, confidence_set in (
            ("high_medium", {"high", "medium"}),
            ("low_report_only", {"low"}),
        ):
            predicted = {
                row["endpoint"] for row in item["actual"] if row["confidence"] in confidence_set
            }
            tier_totals[tier]["tp"] += len(expected_endpoints & predicted)
            tier_totals[tier]["fp"] += len(predicted - expected_endpoints)
            tier_totals[tier]["fn"] += len(expected_endpoints - predicted)
    gate = (
        bool(supported)
        and precision == recall == 1.0
        and hm_controls == 0
        and all(item["status"] == "passed" for item in supported)
        and all(item["status"] in {"passed", "unsupported"} for item in records)
    )
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        revision = "unknown"

    def version(name: str) -> str:
        try:
            return importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            return "unavailable"

    runtime = {
        "python": platform.python_version(),
        "mypy": version("mypy"),
        "fastapi": version("fastapi"),
        "pydantic": version("pydantic"),
        "ruff": version("ruff"),
    }
    harness_hash = "sha256:unavailable"
    with contextlib.suppress(OSError):
        harness_hash = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def tier_record(name: str) -> dict[str, int | float | None]:
        metrics = tier_totals[name]
        denominator = metrics["tp"] + metrics["fp"]
        recall_denominator = metrics["tp"] + metrics["fn"]
        return {
            **metrics,
            "precision": metrics["tp"] / denominator if denominator else None,
            "recall": metrics["tp"] / recall_denominator if recall_denominator else None,
        }

    doc = {
        "schema": SCHEMA,
        "gate_status": "passed" if gate else "failed",
        "pass_criteria": "100% precision/recall; zero HIGH/MEDIUM dead/unrelated candidates",
        "revision": revision,
        "tool_revision_hash": sha(revision),
        "harness_sha256": harness_hash,
        "dependency_versions": runtime,
        "dependency_version_hash": sha(json.dumps(runtime, sort_keys=True)),
        "runtime": runtime,
        "configuration": {
            "backend": "mypy",
            "secure_ast": True,
            "transitive": True,
            "cache": False,
        },
        "configuration_hash": sha(
            json.dumps(
                {"backend": "mypy", "secure_ast": True, "transitive": True, "cache": False},
                sort_keys=True,
            )
        ),
        "case_coverage": {
            "declared": len(CASES),
            "recorded": len(records),
            "supported": sum(case.supported for case in CASES),
            "unsupported": sum(not case.supported for case in CASES),
        },
        "metrics": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "high_medium_control_candidates": hm_controls,
            "high_medium": tier_record("high_medium"),
            "low_report_only": tier_record("low_report_only"),
        },
        "limitations": [
            "additions, deletions, and renames are unsupported by the target-only mypy mapper",
            "this gate does not satisfy GH283 corpus, blind-release, or performance milestones",
        ],
        "unresolved_status": "open: original GH283 corpus and release milestones remain unmeasured",
        "cases": records,
    }
    validate(doc)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=RESULTS / "latest.json")
    args = parser.parse_args()
    doc = run(args.output)
    print(
        json.dumps(
            {
                "gate_status": doc["gate_status"],
                "metrics": doc["metrics"],
                "output": str(args.output),
            }
        )
    )
    return 0 if doc["gate_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
