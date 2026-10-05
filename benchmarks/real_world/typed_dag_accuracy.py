#!/usr/bin/env python3
"""Fail-closed generated typed-DAG accuracy gate; synthetic source is never executed."""

from __future__ import annotations

import argparse
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
    expected: tuple[str, ...]
    control: bool = False
    supported: bool = True
    change_kind: str = "replacement"


# Independent fixture edge specification, with endpoint roots and explicit
# reconvergence. Reachability below consults only this table, never analyzer data.
EDGES = {
    "route_one": ("direct_one", "lambda_live", "awaited_live"),
    "route_two": ("right_live",),
    "direct_one": ("shared_live",),
    "right_live": ("shared_live",),
    "shared_live": ("leaf_alias",),
    "lambda_live": ("leaf_alias",),
    "awaited_live": ("leaf_async",),
    "leaf_async": ("leaf_alias",),
    "literal_false_dead": (),
    "post_return_dead": (),
    "deferred_closure_dead": (),
    "deferred_lambda_dead": (),
    "unawaited_coroutine_dead": (),
    "unrelated_dead": (),
}
CASES = (
    Case("cross_file_alias_reconvergent_leaf", "leaf_alias", ()),
    Case("cross_file_direct", "direct_one", ()),
    Case("shared_helper", "shared_live", ()),
    Case("live_lambda", "lambda_live", ()),
    Case("live_awaited_coroutine", "awaited_live", ()),
    Case("literal_false_control", "literal_false_dead", (), True),
    Case("post_return_control", "post_return_dead", (), True),
    Case("deferred_closure_control", "deferred_closure_dead", (), True),
    Case("deferred_lambda_control", "deferred_lambda_dead", (), True),
    Case("unawaited_coroutine_control", "unawaited_coroutine_dead", (), True),
    Case("unrelated_disconnected_control", "unrelated_dead", (), True),
    Case("addition_unsupported", "added", (), False, False, "addition"),
    Case("deletion_unsupported", "deleted", (), False, False, "deletion"),
    Case("rename_unsupported", "renamed", (), False, False, "rename"),
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
    }
    if symbol in body_tokens:
        bodies[symbol] = replacement
    for name, token in body_tokens.items():
        service = service.replace(token, bodies[name])
    route = """from fastapi import FastAPI
from .service import direct_one, right_live, lambda_live, awaited_live, unawaited_coroutine_dead
app = FastAPI()
@app.get("/one")
async def route_one() -> int:
    unawaited_coroutine_dead()
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


def validate(document: dict[str, Any]) -> None:  # noqa: PLR0912, PLR0915
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
    for case in cases:
        if case.get("status") not in {"passed", "failed", "unsupported"}:
            raise ValueError(f"invalid case status: {case.get('case_id')}")
        declared = next(item for item in CASES if item.case_id == case["case_id"])
        if bool(case.get("supported")) != declared.supported:
            raise ValueError(f"support status mismatch: {case['case_id']}")
        if not declared.supported and case["status"] != "unsupported":
            raise ValueError(f"unsupported case cannot satisfy the gate: {case['case_id']}")
        if declared.supported and case["status"] == "unsupported":
            raise ValueError(f"supported case cannot be skipped: {case['case_id']}")
        if case.get("expected") != list(oracle(declared.symbol)):
            raise ValueError(f"oracle mismatch: {case['case_id']}")
        material = case.get("input_material")
        hashes = case.get("input_hashes")
        if (
            not isinstance(material, dict)
            or not isinstance(hashes, dict)
            or {k: sha(v) for k, v in material.items()} != hashes
        ):
            raise ValueError(f"tampered/missing input hashes: {case['case_id']}")
        if case["supported"]:
            for metric in ("precision", "recall"):
                if not isinstance(case.get(metric), (int, float)) or not math.isfinite(
                    case[metric]
                ):
                    raise ValueError(f"non-finite {metric}: {case['case_id']}")
            actual_keys = [(row["endpoint"], row["confidence"]) for row in case["actual"]]
            if len(actual_keys) != len(set(actual_keys)):
                raise ValueError(f"duplicate candidates: {case['case_id']}")
            if any(row["confidence"] not in {"high", "medium", "low"} for row in case["actual"]):
                raise ValueError(f"invalid confidence tier: {case['case_id']}")
            _metric(case)
    supported = [case for case in cases if case["supported"]]
    derived_pass = (
        bool(supported)
        and all(
            case["precision"] == 1.0
            and case["recall"] == 1.0
            and not (
                case["control"]
                and any(row["confidence"] in {"high", "medium"} for row in case["actual"])
            )
            for case in supported
        )
        and all(case["status"] == "passed" for case in supported)
    )
    metrics = document.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("missing aggregate metrics")
    counts = {key: sum(case[key] for case in supported) for key in ("tp", "fp", "fn")}
    denominator = counts["tp"] + counts["fp"]
    recall_denominator = counts["tp"] + counts["fn"]
    aggregate = {
        **counts,
        "precision": counts["tp"] / denominator
        if denominator
        else (1.0 if not counts["fn"] else 0.0),
        "recall": counts["tp"] / recall_denominator if recall_denominator else 1.0,
        "high_medium_control_candidates": sum(
            row["confidence"] in {"high", "medium"}
            for case in supported
            if case["control"]
            for row in case["actual"]
        ),
    }
    if any(metrics.get(key) != value for key, value in aggregate.items()):
        raise ValueError("aggregate metrics do not match case rows")
    if any(
        isinstance(metrics.get(key), float) and not math.isfinite(metrics[key])
        for key in ("precision", "recall")
    ):
        raise ValueError("non-finite aggregate metric")
    if document.get("gate_status") != ("passed" if derived_pass else "failed"):
        raise ValueError("gate status contradicts validated metrics")


def execute_case(case: Case, root: Path) -> dict[str, Any]:
    original = sources(case.symbol, "return 1")
    changed_text = "leaf_alias() + 1" if case.symbol == "deferred_lambda_dead" else "return 2"
    modified = sources(case.symbol, changed_text)
    changed_path = "app/helpers.py" if case.symbol == "leaf_alias" else "app/service.py"
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
    material = {
        "baseline": json.dumps(original, sort_keys=True),
        "target": json.dumps(modified, sort_keys=True),
        "diff": patch,
        "config": json.dumps(
            {"secure_ast": True, "backend": "mypy", "transitive": True, "cache": False},
            sort_keys=True,
        ),
    }
    expected = expected_for(case)
    if not case.supported:
        return {
            "case_id": case.case_id,
            "symbol": case.symbol,
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
            "input_material": material,
        }
    target = root / case.case_id / "target"
    for rel, text in modified.items():
        path = target / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    diff_path = root / f"{case.case_id}.diff"
    diff_path.write_text(patch, encoding="utf-8")
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
    actual = []
    for candidate in report.get("candidate_endpoints", []):
        endpoint = candidate["endpoint"]
        actual.append(
            {
                "endpoint": f"{endpoint.get('method', 'GET')} {endpoint.get('path', '')}",
                "confidence": str(candidate["confidence"]).lower().split(".")[-1],
            }
        )
    actual.sort(key=lambda row: (row["endpoint"], row["confidence"]))
    predicted = {row["endpoint"] for row in actual}
    expected_endpoints = set(expected)
    tp, fp, fn = (
        len(predicted & expected_endpoints),
        len(predicted - expected_endpoints),
        len(expected_endpoints - predicted),
    )
    precision = tp / (tp + fp) if tp + fp else (1.0 if not expected_endpoints else 0.0)
    recall = tp / (tp + fn) if tp + fn else 1.0
    passed = (
        precision == recall == 1.0
        and not report.get("errors")
        and not (case.control and any(row["confidence"] in {"high", "medium"} for row in actual))
    )
    return {
        "case_id": case.case_id,
        "symbol": case.symbol,
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
        "total_endpoints": report.get("total_endpoints"),
        "analyzer_errors": report.get("errors", []),
        "analyzer_warnings": report.get("warnings", []),
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
                original = sources(case.symbol, "return 1")
                target = sources(case.symbol, "return 2")
                selected_path = (
                    "app/helpers.py" if case.symbol == "leaf_alias" else "app/service.py"
                )
                material = {
                    "baseline": json.dumps(original, sort_keys=True),
                    "target": json.dumps(target, sort_keys=True),
                    "diff": make_diff(
                        selected_path, original[selected_path], target[selected_path]
                    ),
                    "config": json.dumps(
                        {"secure_ast": True, "backend": "mypy", "transitive": True, "cache": False},
                        sort_keys=True,
                    ),
                    "error": str(exc),
                }
                expected = list(oracle(case.symbol))
                record = {
                    "case_id": case.case_id,
                    "symbol": case.symbol,
                    "supported": case.supported,
                    "control": case.control,
                    "status": "failed",
                    "expected": expected,
                    "actual": [],
                    "tp": 0,
                    "fp": 0,
                    "fn": len(expected),
                    "precision": 0.0,
                    "recall": 0.0,
                    "error": str(exc),
                    "input_material": material,
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
            "supported": len(supported),
            "unsupported": len(records) - len(supported),
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
