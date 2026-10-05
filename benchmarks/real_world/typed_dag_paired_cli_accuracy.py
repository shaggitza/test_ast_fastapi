#!/usr/bin/env python3
"""Paired CLI accuracy validation for deterministic generated FastAPI DAGs.

The harness source and the installed analyzer may come from different git
revisions. Synthetic fixtures are parsed only through the analyzer's secure
AST mode; this harness never imports or executes them.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import difflib
import hashlib
import json
import math
import os
import platform
import secrets
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

# Keep direct-file invocation equivalent to ``python -m`` for the harness-only
# independent oracle import. This path is never passed to the analyzer process.
HARNESS_ROOT = Path(__file__).resolve().parents[2]
if str(HARNESS_ROOT) not in sys.path:
    sys.path.insert(0, str(HARNESS_ROOT))

from benchmarks.real_world import typed_dag_accuracy as v1  # noqa: E402

SCHEMA = "typed-dag-paired-cli-accuracy-v2"
RESULTS = Path(__file__).resolve().parents[1] / "results" / SCHEMA
CLI_TIMEOUT_SECONDS = 240
CLI_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
ROOTS = v1.ROOTS


@dataclass(frozen=True)
class Case:
    case_id: str
    symbol: str
    control: bool = False
    change_kind: str = "replacement"
    source_symbol: str | None = None
    capability_probe: bool = False


CASES = (
    *(
        Case(
            case.case_id,
            case.symbol,
            case.control,
            case.change_kind,
            case.source_symbol,
        )
        for case in v1.CASES[:15]
    ),
    Case("addition_capability_probe", "added", change_kind="addition", capability_probe=True),
    Case("deletion_capability_probe", "deleted", change_kind="deletion", capability_probe=True),
    Case("rename_capability_probe", "renamed", change_kind="rename", capability_probe=True),
)
_BASE_CASES = {case.case_id: case for case in v1.CASES}


def sha_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha_text(value: str) -> str:
    return sha_bytes(value.encode("utf-8"))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _lines_diff(path: str, before: str | None, after: str | None) -> str:
    left = before.splitlines(keepends=True) if before is not None else []
    right = after.splitlines(keepends=True) if after is not None else []
    old_name = f"a/{path}" if before is not None else "/dev/null"
    new_name = f"b/{path}" if after is not None else "/dev/null"
    return "".join(difflib.unified_diff(left, right, fromfile=old_name, tofile=new_name))


def _require_replace(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError(f"fixture source did not contain one expected fragment: {old!r}")
    return source.replace(old, new)


def _route_with_call(source: str, import_line: str, call_line: str) -> str:
    service_import = next(
        (
            line
            for line in source.splitlines(keepends=True)
            if line.startswith("from .service import")
        ),
        None,
    )
    if service_import is None:
        raise ValueError("generated route module lost service imports")
    source = _require_replace(source, service_import, service_import + import_line + "\n")
    return _require_replace(
        source, "    return direct_one()", f"    {call_line}\n    return direct_one()"
    )


def _capability_inputs(kind: str) -> dict[str, str]:
    baseline = v1.sources("direct_one", "return shared_live()")
    target = dict(baseline)
    if kind == "addition":
        target["app/added.py"] = "def added() -> int:\n    return 7\n"
        target["app/routes.py"] = _route_with_call(
            target["app/routes.py"], "from .added import added", "added()"
        )
    elif kind == "deletion":
        baseline["app/deleted.py"] = "def deleted() -> int:\n    return 7\n"
        baseline["app/routes.py"] = _route_with_call(
            baseline["app/routes.py"], "from .deleted import deleted", "deleted()"
        )
        target = dict(baseline)
        target.pop("app/deleted.py")
        # Preserve the generated modules while restoring the target route that
        # no longer imports or invokes the removed helper.
        standard_sources = v1.sources("direct_one", "return shared_live()")
        target["app/routes.py"] = standard_sources["app/routes.py"]
    elif kind == "rename":
        baseline["app/renamed.py"] = "def old_name() -> int:\n    return 7\n"
        baseline["app/routes.py"] = _route_with_call(
            baseline["app/routes.py"], "from .renamed import old_name", "old_name()"
        )
        target = dict(baseline)
        target["app/renamed.py"] = "def new_name() -> int:\n    return 7\n"
        route = baseline["app/routes.py"]
        if route.count("old_name") != 2:
            raise ValueError("rename fixture must include one import and one call")
        target["app/routes.py"] = route.replace("old_name", "new_name")
    else:
        raise ValueError(f"unknown capability probe: {kind}")

    diff = "".join(
        _lines_diff(path, baseline.get(path), target.get(path))
        for path in sorted(set(baseline) | set(target))
        if baseline.get(path) != target.get(path)
    )
    return {
        "baseline": json.dumps(baseline, sort_keys=True),
        "target": json.dumps(target, sort_keys=True),
        "diff": diff,
        "config": json.dumps(
            {
                "secure_ast": True,
                "backend": "mypy",
                "transitive": True,
                "cache": False,
                "paired_baseline_target": True,
            },
            sort_keys=True,
        ),
    }


def case_inputs(case: Case) -> dict[str, str]:
    if case.capability_probe:
        return _capability_inputs(case.change_kind)
    material = v1.case_inputs(_BASE_CASES[case.case_id])
    config = json.loads(material["config"])
    config["paired_baseline_target"] = True
    material["config"] = json.dumps(config, sort_keys=True)
    return material


def _oracle_edges(extra: dict[str, tuple[str, ...]], symbol: str) -> tuple[str, ...]:
    edges = dict(v1.EDGES)
    for caller, callees in extra.items():
        edges[caller] = (*edges.get(caller, ()), *callees)
    reverse: dict[str, set[str]] = {}
    for caller, callees in edges.items():
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
    if case.change_kind == "addition":
        return _oracle_edges({"route_one": ("added",)}, case.symbol)
    if case.change_kind == "deletion":
        return _oracle_edges({"route_one": ("deleted",)}, case.symbol)
    if case.change_kind == "rename":
        return tuple(
            sorted(
                set(_oracle_edges({"route_one": ("old_name",)}, "old_name"))
                | set(_oracle_edges({"route_one": ("new_name",)}, "new_name"))
            )
        )
    return v1.oracle(case.symbol)


def validate_generated_fixture(case: Case, material: dict[str, str]) -> None:  # noqa: PLR0912
    if material != case_inputs(case):
        raise ValueError(f"source/diff/config do not match generator: {case.case_id}")
    if not case.capability_probe:
        original = v1.case_inputs(_BASE_CASES[case.case_id])
        original["config"] = json.dumps(json.loads(original["config"]), sort_keys=True)
        v1.validate_generated_fixture(_BASE_CASES[case.case_id], original)
        return

    baseline = json.loads(material["baseline"])
    target = json.loads(material["target"])
    for snapshot in (baseline, target):
        ast.parse(snapshot["app/routes.py"])
    if case.change_kind == "addition":
        if "app/added.py" in baseline or "app/added.py" not in target:
            raise ValueError("addition capability fixture must be paired baseline/target")
        if "added()" not in target["app/routes.py"] or "added()" in baseline["app/routes.py"]:
            raise ValueError("added helper must have a target-only route call")
    elif case.change_kind == "deletion":
        if "app/deleted.py" not in baseline or "app/deleted.py" in target:
            raise ValueError("deletion capability fixture must be paired baseline/target")
        if "deleted()" not in baseline["app/routes.py"] or "deleted()" in target["app/routes.py"]:
            raise ValueError("deleted helper must have a baseline-only route call")
    elif case.change_kind == "rename":
        if (
            "old_name" not in baseline["app/renamed.py"]
            or "new_name" not in target["app/renamed.py"]
        ):
            raise ValueError("rename capability fixture must bind old and new symbols")
        if (
            "old_name()" not in baseline["app/routes.py"]
            or "new_name()" not in target["app/routes.py"]
        ):
            raise ValueError("renamed helper must remain endpoint-reachable on both sides")
    if not expected_for(case):
        raise ValueError(f"capability fixture has no oracle endpoint impact: {case.case_id}")


def _source_inventory(analyzer_root: Path, revision: str) -> dict[str, str]:
    paths = _git(
        analyzer_root,
        "ls-tree",
        "-r",
        "--name-only",
        revision,
        "--",
        "src/fastapi_endpoint_detector",
        "pyproject.toml",
        "uv.lock",
    ).splitlines()
    relevant_suffixes = {".py", ".json", ".toml", ".yaml", ".yml", ".txt", ".jinja", ".jinja2"}
    selected = [
        relative
        for relative in paths
        if relative in {"pyproject.toml", "uv.lock"} or Path(relative).suffix in relevant_suffixes
    ]
    inventory: dict[str, str] = {}
    for relative in selected:
        committed = subprocess.run(
            ["git", "-C", str(analyzer_root), "show", f"{revision}:{relative}"],
            capture_output=True,
            check=True,
        ).stdout
        working = (analyzer_root / relative).read_bytes()
        if committed != working:
            raise ValueError(f"analyzer source differs from pinned commit: {relative}")
        inventory[relative] = sha_bytes(working)
    return inventory


def _analyzer_environment(analyzer_root: Path) -> dict[str, str]:
    script = (
        "import importlib.metadata as m, json, shutil, sys, fastapi_endpoint_detector, "
        "fastapi_endpoint_detector.cli; "
        "print(json.dumps({'python':sys.version.split()[0],"
        "'module':fastapi_endpoint_detector.__file__,"
        "'cli_module':fastapi_endpoint_detector.cli.__file__,"
        "'cli_entrypoint':shutil.which('fastapi-endpoint-detector'),"
        "'mypy':m.version('mypy'),'fastapi':m.version('fastapi'),"
        "'pydantic':m.version('pydantic')}))"
    )
    result = subprocess.run(
        ["uv", "run", "--project", str(analyzer_root), "python", "-c", script],
        cwd=analyzer_root,
        capture_output=True,
        text=True,
        check=True,
        timeout=90,
    )
    environment = cast("dict[str, str]", json.loads(result.stdout))
    source_root = (analyzer_root / "src").resolve()
    for key in ("module", "cli_module"):
        Path(environment[key]).resolve().relative_to(source_root)
    entrypoint = environment.get("cli_entrypoint")
    if not entrypoint:
        raise ValueError("analyzer project does not expose the installed CLI entrypoint")
    environment["cli_entrypoint_sha256"] = sha_bytes(Path(entrypoint).read_bytes())
    return environment


def analyzer_provenance(analyzer_root: Path) -> dict[str, Any]:
    analyzer_root = analyzer_root.resolve()
    revision = _git(analyzer_root, "rev-parse", "HEAD")
    dirty = _git(analyzer_root, "status", "--porcelain", "--untracked-files=all")
    if dirty:
        raise ValueError("analyzer worktree must be clean to pin actual source bytes")
    sources = _source_inventory(analyzer_root, revision)
    return {
        "revision": revision,
        "revision_hash": sha_text(revision),
        "source_root": str(analyzer_root),
        "worktree_clean": True,
        "source_sha256": sources,
        "source_tree_hash": sha_text(_canonical_json(sources)),
        "environment": _analyzer_environment(analyzer_root),
    }


def _source_identity_snapshot(analyzer_root: Path, pinned: dict[str, str]) -> dict[str, Any]:
    try:
        current = {
            relative: sha_bytes((analyzer_root / relative).read_bytes()) for relative in pinned
        }
        clean = not bool(_git(analyzer_root, "status", "--porcelain", "--untracked-files=all"))
    except (OSError, subprocess.CalledProcessError):
        current = {}
        clean = False
    return {
        "worktree_clean": clean,
        "source_tree_hash": sha_text(_canonical_json(current)),
        "source_sha256": current,
    }


def validate_provenance(document: dict[str, Any], analyzer_root: Path) -> None:
    actual = analyzer_provenance(analyzer_root)
    expected = document.get("analyzer_provenance")
    if expected != actual:
        raise ValueError("analyzer revision/source-byte provenance differs from pinned input")


def _actual_from_report(report: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for candidate in report.get("candidate_endpoints", []):
        endpoint = candidate["endpoint"]
        rows.append(
            {
                "endpoint": f"{endpoint.get('method', 'GET')} {endpoint.get('path', '')}",
                "confidence": str(candidate["confidence"]).lower().split(".")[-1],
            }
        )
    return sorted(rows, key=lambda row: (row["endpoint"], row["confidence"]))


def _metrics(expected: list[str], actual: list[dict[str, str]]) -> dict[str, Any]:
    expected_set = set(expected)
    predicted = {row["endpoint"] for row in actual}
    tp, fp, fn = (
        len(expected_set & predicted),
        len(predicted - expected_set),
        len(expected_set - predicted),
    )
    precision = tp / (tp + fp) if tp + fp else (1.0 if not expected_set else 0.0)
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall}


def _tier_metrics(cases: list[dict[str, Any]], tiers: set[str]) -> dict[str, Any]:
    tp = fp = fn = 0
    for case in cases:
        expected = set(case["expected"])
        predicted = {row["endpoint"] for row in case["actual"] if row["confidence"] in tiers}
        tp += len(expected & predicted)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else (1.0 if not fn else 0.0),
    }


def _gate_passed(
    cases: list[dict[str, Any]], coverage: dict[str, int], metrics: dict[str, Any]
) -> bool:
    supported = [case for case in cases if case.get("supported") is True]
    return (
        bool(supported)
        and coverage["unsupported"] == 0
        and coverage["failed"] == 0
        and all(case.get("status") == "passed" for case in cases)
        and all(case.get("status") == "passed" for case in supported)
        and metrics["precision"] == metrics["recall"] == 1.0
        and metrics["high_medium_control_candidates"] == 0
    )


def _explicit_unsupported(report: dict[str, Any]) -> str | None:
    details = [
        *report.get("warnings", []),
        *report.get("inventory_limitations", []),
    ]
    for detail in details:
        lowered = str(detail).lower()
        if "unsupported" in lowered or "not supported" in lowered or "unresolved orphan" in lowered:
            return str(detail)
    return None


def _case_passes(record: dict[str, Any], declared: Case) -> bool:
    report = record.get("cli_evidence", {}).get("report")
    if not isinstance(report, dict):
        return False
    return (
        record["precision"] == 1.0
        and record["recall"] == 1.0
        and not report.get("errors")
        and report.get("inventory_status") == "established"
        and report.get("summary", {}).get("total_endpoints") == len(ROOTS)
        and not report.get("inventory_limitations")
        and not (
            declared.control
            and any(row["confidence"] in {"high", "medium"} for row in record["actual"])
        )
    )


def _validate_synthetic_probe(document: dict[str, Any]) -> None:  # noqa: PLR0912
    """Validate in-memory mutation probes without admitting them as run evidence."""
    if document.get("gate_status") != "failed":
        raise ValueError("synthetic validation documents cannot claim a passing gate")
    rows = document.get("cases")
    if not isinstance(rows, list) or len(rows) != len(CASES):
        raise ValueError("synthetic case coverage is incomplete")
    ids = [row.get("case_id") for row in rows]
    if len(ids) != len(set(ids)) or set(ids) != {case.case_id for case in CASES}:
        raise ValueError("duplicate, missing, or undeclared synthetic cases")
    declared_by_id = {case.case_id: case for case in CASES}
    for row in rows:
        declared = declared_by_id[row["case_id"]]
        metadata = {
            "symbol": declared.symbol,
            "source_symbol": declared.source_symbol,
            "control": declared.control,
            "change_kind": declared.change_kind,
            "capability_probe": declared.capability_probe,
        }
        if any(row.get(key) != value for key, value in metadata.items()):
            raise ValueError(f"synthetic case metadata mismatch: {declared.case_id}")
        if row.get("status") != "failed" or row.get("cli_evidence") is not None:
            raise ValueError("synthetic documents must remain failed and contain no CLI evidence")
        if not row.get("error"):
            raise ValueError("synthetic failure must be explicit")
        if row.get("actual") != []:
            raise ValueError("synthetic validation probes cannot invent candidates")
        if row.get("supported") is not (not declared.capability_probe):
            raise ValueError(f"synthetic support metadata mismatch: {declared.case_id}")
        expected = list(expected_for(declared))
        if row.get("expected") != expected:
            raise ValueError(f"synthetic oracle mismatch: {declared.case_id}")
        material = case_inputs(declared)
        if row.get("input_material") != material:
            raise ValueError(f"synthetic fixture material mismatch: {declared.case_id}")
        if row.get("input_hashes") != {key: sha_text(value) for key, value in material.items()}:
            raise ValueError(f"synthetic input hashes mismatch: {declared.case_id}")
        validate_generated_fixture(declared, material)
        metrics = _metrics(expected, [])
        if any(row.get(key) != value for key, value in metrics.items()):
            raise ValueError(f"synthetic metrics mismatch: {declared.case_id}")

    supported = [row for row in rows if row["supported"]]
    coverage = {
        "declared": len(CASES),
        "recorded": len(rows),
        "supported": len(supported),
        "unsupported": 0,
        "failed": len(rows),
    }
    if document.get("case_coverage") != coverage:
        raise ValueError("synthetic case coverage mismatch")
    tp = sum(row["tp"] for row in supported)
    fp = sum(row["fp"] for row in supported)
    fn = sum(row["fn"] for row in supported)
    totals = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else (1.0 if not fn else 0.0),
        "recall": tp / (tp + fn) if tp + fn else 1.0,
        "high_medium_control_candidates": 0,
        "high_medium": _tier_metrics(supported, {"high", "medium"}),
        "low_report_only": _tier_metrics(supported, {"low"}),
    }
    if document.get("metrics") != totals:
        raise ValueError("synthetic aggregate metrics mismatch")


def validate(  # noqa: PLR0912, PLR0915
    document: dict[str, Any],
    analyzer_root: Path | None = None,
    execution_context: _ExecutionContext | None = None,
) -> None:
    if document.get("schema") != SCHEMA:
        raise ValueError("invalid schema")
    if document.get("evidence_kind") == "synthetic_validation_only":
        _validate_synthetic_probe(document)
        return
    if document.get("evidence_kind") != "cli_generated":
        raise ValueError("only v2 CLI-generated evidence is valid gate input")
    if (
        document.get("run_validity") != "valid"
        or document.get("integrity_errors") != []
        or document.get("final_source_identity", {}).get("worktree_clean") is not True
        or document.get("final_source_identity", {}).get("source_tree_hash")
        != document.get("analyzer_provenance", {}).get("source_tree_hash")
    ):
        raise ValueError("run or final analyzer source identity is invalid")
    if not isinstance(execution_context, _ExecutionContext):
        raise ValueError(
            "serialized CLI evidence is replay-only; validation requires the in-memory "
            "subprocess execution context"
        )
    runner = document.get("runner_provenance")
    if not isinstance(runner, dict):
        raise ValueError("runner provenance is missing")
    if runner.get("revision_hash") != sha_text(str(runner.get("revision", ""))):
        raise ValueError("runner revision hash is invalid")
    runner_root = Path(__file__).resolve().parents[2]
    if Path(str(runner.get("root", ""))).resolve() != runner_root:
        raise ValueError("runner root differs from this harness checkout")
    runner_revision = str(runner.get("revision", ""))
    for relative, field in (
        ("benchmarks/real_world/typed_dag_paired_cli_accuracy.py", "harness_sha256"),
        ("benchmarks/real_world/typed_dag_accuracy.py", "fixture_generator_sha256"),
    ):
        committed = subprocess.run(
            ["git", "-C", str(runner_root), "show", f"{runner_revision}:{relative}"],
            check=True,
            capture_output=True,
        ).stdout
        if runner.get(field) != sha_bytes(committed):
            raise ValueError(f"runner {relative} differs from pinned commit bytes")
    if runner.get("harness_sha256") != sha_bytes(Path(__file__).read_bytes()):
        raise ValueError("tampered harness source hash")
    if runner.get("fixture_generator_sha256") != sha_bytes(Path(v1.__file__).read_bytes()):
        raise ValueError("tampered independent fixture generator hash")
    if document.get("configuration_hash") != sha_text(
        _canonical_json(document.get("configuration"))
    ):
        raise ValueError("configuration hash is invalid")
    if analyzer_root is None:
        analyzer_root = Path(str(document.get("analyzer_provenance", {}).get("source_root", "")))
    validate_provenance(document, analyzer_root)

    rows = document.get("cases")
    if not isinstance(rows, list) or len(rows) != len(CASES):
        raise ValueError("case coverage is missing or incomplete")
    ids = [row.get("case_id") for row in rows]
    if len(ids) != len(set(ids)) or set(ids) != {case.case_id for case in CASES}:
        raise ValueError("duplicate, missing, or undeclared cases")

    declared_by_id = {case.case_id: case for case in CASES}
    for row in rows:
        declared = declared_by_id[row["case_id"]]
        if row.get("status") not in {"passed", "failed", "unsupported"}:
            raise ValueError(f"invalid case status: {declared.case_id}")
        metadata = {
            "symbol": declared.symbol,
            "source_symbol": declared.source_symbol,
            "control": declared.control,
            "change_kind": declared.change_kind,
            "capability_probe": declared.capability_probe,
        }
        if any(row.get(key) != value for key, value in metadata.items()):
            raise ValueError(f"case metadata mismatch: {declared.case_id}")
        expected_tree_hash = document["analyzer_provenance"]["source_tree_hash"]
        if row.get("source_identity_valid") is not True:
            raise ValueError(f"analyzer source identity is untrusted: {declared.case_id}")
        for side in ("source_identity_before", "source_identity_after"):
            identity = row.get(side)
            if (
                not isinstance(identity, dict)
                or identity.get("worktree_clean") is not True
                or identity.get("source_tree_hash") != expected_tree_hash
                or identity.get("source_sha256") != document["analyzer_provenance"]["source_sha256"]
            ):
                raise ValueError(f"analyzer changed during case: {declared.case_id}")
        expected_material = case_inputs(declared)
        if row.get("expected") != list(expected_for(declared)):
            raise ValueError(
                f"expected endpoints differ from independent oracle: {declared.case_id}"
            )
        if row.get("input_material") != expected_material:
            raise ValueError(f"generated baseline/target/diff/config mismatch: {declared.case_id}")
        if row.get("input_hashes") != {
            key: sha_text(value) for key, value in expected_material.items()
        }:
            raise ValueError(f"input hash mismatch: {declared.case_id}")
        validate_generated_fixture(declared, expected_material)
        evidence = row.get("cli_evidence")
        if not isinstance(evidence, dict):
            if row.get("status") != "failed" or not row.get("error"):
                raise ValueError(f"missing CLI evidence must fail explicitly: {declared.case_id}")
            continue
        if not execution_context.verify(row):
            raise ValueError(
                f"CLI evidence lacks an in-process subprocess receipt: {declared.case_id}"
            )
        report = evidence.get("report")
        if report is None:
            if row.get("status") != "failed" or not row.get("error"):
                raise ValueError(f"missing CLI report must fail explicitly: {declared.case_id}")
            continue
        if not isinstance(report, dict) or evidence.get("report_hash") != sha_text(
            _canonical_json(report)
        ):
            raise ValueError(f"CLI report hash mismatch: {declared.case_id}")
        if evidence.get("stdout_sha256") != sha_text(str(evidence.get("stdout", ""))):
            raise ValueError(f"CLI stdout hash mismatch: {declared.case_id}")
        try:
            if json.loads(evidence["stdout"]) != report:
                raise ValueError(f"CLI stdout JSON differs from report: {declared.case_id}")
        except (KeyError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"CLI stdout is missing valid JSON: {declared.case_id}") from exc
        if evidence.get("stderr_sha256") != sha_text(str(evidence.get("stderr", ""))):
            raise ValueError(f"CLI stderr hash mismatch: {declared.case_id}")
        if evidence.get("exit_code") != 0 and row.get("status") != "failed":
            raise ValueError(f"nonzero CLI result cannot pass: {declared.case_id}")
        if "--baseline-app" not in evidence.get("options", []):
            raise ValueError(f"case did not run with paired baseline interface: {declared.case_id}")
        for option in ("--diff", "--secure-ast", "--no-cache", "--format", "json"):
            if option not in evidence["options"]:
                raise ValueError(f"case lacks a required CLI option: {declared.case_id}")
        command = evidence.get("command")
        if evidence["options"].count("--baseline-app") != 1:
            raise ValueError(f"baseline app must be supplied exactly once: {declared.case_id}")
        for option in ("--app", "--baseline-app", "--diff"):
            if evidence["options"].count(option) != 1:
                raise ValueError(f"CLI path option is missing or duplicated: {declared.case_id}")
        if (
            not isinstance(command, list)
            or command[:4]
            != [
                "uv",
                "run",
                "--project",
                document["analyzer_provenance"]["source_root"],
            ]
            or command[-len(evidence["options"]) :] != evidence["options"]
            or evidence.get("command_hash") != sha_text(_canonical_json(command))
        ):
            raise ValueError(f"CLI command differs from pinned analyzer: {declared.case_id}")
        elapsed_ms = evidence.get("elapsed_ms")
        if (
            not isinstance(elapsed_ms, (int, float))
            or not math.isfinite(elapsed_ms)
            or elapsed_ms < 0
        ):
            raise ValueError(f"invalid CLI timing: {declared.case_id}")
        output_bytes = sum(
            len(str(evidence.get(key, "")).encode("utf-8")) for key in ("stdout", "stderr")
        )
        if (
            evidence.get("output_limit_bytes") != CLI_OUTPUT_LIMIT_BYTES
            or output_bytes > CLI_OUTPUT_LIMIT_BYTES
            or evidence.get("output_limit_exceeded") is True
            or evidence.get("timed_out") is True
        ) and row.get("status") != "failed":
            raise ValueError(f"CLI output exceeded its bounds: {declared.case_id}")
        actual = _actual_from_report(report)
        if any(row["confidence"] not in {"high", "medium", "low"} for row in actual):
            raise ValueError(f"invalid confidence tier: {declared.case_id}")
        if actual != row.get("actual"):
            raise ValueError(f"candidate rows differ from CLI report: {declared.case_id}")
        candidate_keys = [(item["endpoint"], item["confidence"]) for item in actual]
        if len(candidate_keys) != len(set(candidate_keys)):
            raise ValueError(f"duplicate candidate rows: {declared.case_id}")
        metrics = _metrics(row["expected"], actual)
        if any(row.get(key) != value for key, value in metrics.items()):
            raise ValueError(f"case metrics differ from candidate rows: {declared.case_id}")
        if row.get("analyzer_errors") != report.get("errors", []):
            raise ValueError(f"analyzer errors differ from CLI report: {declared.case_id}")
        if row.get("analyzer_warnings") != report.get("warnings", []):
            raise ValueError(f"analyzer warnings differ from CLI report: {declared.case_id}")
        if row.get("inventory_status") != report.get("inventory_status"):
            raise ValueError(f"inventory status differs from CLI report: {declared.case_id}")
        if row.get("inventory_limitations") != report.get("inventory_limitations", []):
            raise ValueError(f"inventory limitations differ from CLI report: {declared.case_id}")
        if row.get("total_endpoints") != report.get("summary", {}).get("total_endpoints"):
            raise ValueError(f"endpoint count differs from CLI report: {declared.case_id}")
        if evidence.get("exit_code") != 0:
            continue

        unsupported_reason = _explicit_unsupported(report) if declared.capability_probe else None
        if unsupported_reason:
            if row.get("status") != "unsupported" or row.get("supported") is not False:
                raise ValueError(
                    f"capability was not marked explicitly unsupported: {declared.case_id}"
                )
        else:
            if not declared.capability_probe and row.get("supported") is not True:
                raise ValueError(f"declared supported case was demoted: {declared.case_id}")
            operational = (
                not report.get("errors")
                and report.get("inventory_status") == "established"
                and report.get("summary", {}).get("total_endpoints") == len(ROOTS)
                and not report.get("inventory_limitations")
            )
            if declared.capability_probe and row.get("supported") is not operational:
                raise ValueError(f"capability support was guessed: {declared.case_id}")
            if row.get("supported") is True and row.get("status") != (
                "passed" if _case_passes(row, declared) else "failed"
            ):
                raise ValueError(f"case status contradicts measured outcome: {declared.case_id}")

    supported = [row for row in rows if row.get("supported") is True]
    coverage = {
        "declared": len(CASES),
        "recorded": len(rows),
        "supported": len(supported),
        "unsupported": sum(row.get("status") == "unsupported" for row in rows),
        "failed": sum(row.get("status") == "failed" for row in rows),
    }
    if document.get("case_coverage") != coverage:
        raise ValueError("case coverage does not match declared and recorded cases")
    run_duration = document.get("run_duration_ms")
    if (
        not isinstance(run_duration, (int, float))
        or not math.isfinite(run_duration)
        or run_duration < 0
    ):
        raise ValueError("invalid run duration")

    overall_tp = sum(row["tp"] for row in supported)
    overall_fp = sum(row["fp"] for row in supported)
    overall_fn = sum(row["fn"] for row in supported)
    overall = {
        "precision": overall_tp / (overall_tp + overall_fp)
        if overall_tp + overall_fp
        else (1.0 if overall_fn == 0 else 0.0),
        "recall": overall_tp / (overall_tp + overall_fn) if overall_tp + overall_fn else 1.0,
    }
    aggregate = {
        "tp": overall_tp,
        "fp": overall_fp,
        "fn": overall_fn,
        **overall,
        "high_medium_control_candidates": sum(
            row["confidence"] in {"high", "medium"}
            for case in supported
            if case["control"]
            for row in case["actual"]
        ),
        "high_medium": _tier_metrics(supported, {"high", "medium"}),
        "low_report_only": _tier_metrics(supported, {"low"}),
    }
    if document.get("metrics") != aggregate:
        raise ValueError("aggregate or tier metrics do not match case records")
    gate_passed = _gate_passed(rows, coverage, aggregate)
    if document.get("gate_status") != ("passed" if gate_passed else "failed"):
        raise ValueError("gate status contradicts measured case coverage and metrics")


def _write_snapshot(root: Path, label: str, sources: dict[str, str]) -> Path:
    app_root = root / label
    for relative, source in sources.items():
        path = app_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return app_root / "app"


@dataclass
class _ExecutionContext:
    """Ephemeral evidence that this process collected each case from a subprocess."""

    secret: str
    receipts: dict[str, str]

    @classmethod
    def create(cls) -> _ExecutionContext:
        return cls(secrets.token_hex(32), {})

    def record(self, case_id: str, evidence: dict[str, Any]) -> None:
        payload = {
            "case_id": case_id,
            "command_hash": evidence["command_hash"],
            "exit_code": evidence["exit_code"],
            "stdout_sha256": evidence["stdout_sha256"],
            "stderr_sha256": evidence["stderr_sha256"],
            "report_hash": evidence["report_hash"],
        }
        evidence["execution_receipt"] = sha_text(self.secret + _canonical_json(payload))
        self.receipts[case_id] = evidence["execution_receipt"]

    def verify(self, row: dict[str, Any]) -> bool:
        evidence = row.get("cli_evidence")
        if not isinstance(evidence, dict):
            return False
        payload = {
            "case_id": row.get("case_id"),
            "command_hash": evidence.get("command_hash"),
            "exit_code": evidence.get("exit_code"),
            "stdout_sha256": evidence.get("stdout_sha256"),
            "stderr_sha256": evidence.get("stderr_sha256"),
            "report_hash": evidence.get("report_hash"),
        }
        case_id = row.get("case_id")
        if not isinstance(case_id, str):
            return False
        expected = sha_text(self.secret + _canonical_json(payload))
        return (
            self.receipts.get(case_id) == expected and evidence.get("execution_receipt") == expected
        )


@dataclass
class _CliResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    output_limit_exceeded: bool


def _run_bounded_cli(command: list[str], cwd: Path, timeout_seconds: int) -> _CliResult:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    selector = selectors.DefaultSelector()
    buffers = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    streams = {stdout_fd: process.stdout, stderr_fd: process.stderr}
    for descriptor, stream in streams.items():
        selector.register(stream, selectors.EVENT_READ, descriptor)
    started = time.perf_counter()
    deadline = started + timeout_seconds
    timed_out = False
    output_limit_exceeded = False
    killed = False
    while selector.get_map():
        remaining = deadline - time.perf_counter()
        if remaining <= 0 and process.poll() is None:
            timed_out = True
        if (timed_out or output_limit_exceeded) and not killed:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            killed = True
        events = selector.select(min(0.1, max(0.0, remaining)))
        for key, _ in events:
            descriptor = key.data
            chunk = os.read(descriptor, 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            total = sum(map(len, buffers.values()))
            room = max(0, CLI_OUTPUT_LIMIT_BYTES - total)
            buffers[descriptor].extend(chunk[:room])
            if len(chunk) > room and not output_limit_exceeded:
                output_limit_exceeded = True
        if process.poll() is not None and not selector.get_map():
            break
    returncode = process.wait()
    selector.close()
    process.stdout.close()
    process.stderr.close()
    return _CliResult(
        returncode,
        buffers[stdout_fd].decode("utf-8", errors="replace"),
        buffers[stderr_fd].decode("utf-8", errors="replace"),
        timed_out,
        output_limit_exceeded,
    )


def _run_case(
    case: Case,
    analyzer_root: Path,
    fixture_root: Path,
    timeout_seconds: int,
    execution_context: _ExecutionContext,
    analyzer_sources: dict[str, str],
) -> dict[str, Any]:
    material = case_inputs(case)
    validate_generated_fixture(case, material)
    baseline_sources = json.loads(material["baseline"])
    target_sources = json.loads(material["target"])
    baseline_app = _write_snapshot(fixture_root / case.case_id, "baseline", baseline_sources)
    target_app = _write_snapshot(fixture_root / case.case_id, "target", target_sources)
    diff_path = fixture_root / f"{case.case_id}.diff"
    diff_path.write_text(material["diff"], encoding="utf-8")
    options = [
        "analyze",
        "--app",
        str(target_app),
        "--baseline-app",
        str(baseline_app),
        "--diff",
        str(diff_path),
        "--format",
        "json",
        "--secure-ast",
        "--no-cache",
    ]
    command = ["uv", "run", "--project", str(analyzer_root), "fastapi-endpoint-detector", *options]
    identity_before = _source_identity_snapshot(analyzer_root, analyzer_sources)
    started = time.perf_counter()
    result = _run_bounded_cli(command, analyzer_root, timeout_seconds)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    identity_after = _source_identity_snapshot(analyzer_root, analyzer_sources)
    source_identity_valid = all(
        identity["worktree_clean"]
        and identity["source_tree_hash"] == sha_text(_canonical_json(analyzer_sources))
        for identity in (identity_before, identity_after)
    )

    report: dict[str, Any] | None = None
    parse_error = None
    try:
        if result.output_limit_exceeded or result.timed_out:
            raise ValueError(
                "CLI output limit exceeded" if result.output_limit_exceeded else "CLI timeout"
            )
        report = json.loads(result.stdout)
        if not isinstance(report, dict):
            raise TypeError("CLI JSON report must be an object")
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        parse_error = str(exc)
    errors = report.get("errors", []) if report else []
    warnings = report.get("warnings", []) if report else []
    actual = _actual_from_report(report) if report else []
    expected = list(expected_for(case))
    metrics = _metrics(expected, actual)
    inventory_status = report.get("inventory_status") if report else None
    inventory_limitations = report.get("inventory_limitations", []) if report else []
    total_endpoints = report.get("summary", {}).get("total_endpoints") if report else None
    operational = (
        result.returncode == 0
        and not result.timed_out
        and not result.output_limit_exceeded
        and source_identity_valid
        and report is not None
        and not errors
        and inventory_status == "established"
        and total_endpoints == len(ROOTS)
        and not inventory_limitations
    )
    unsupported_reason = _explicit_unsupported(report) if report and case.capability_probe else None
    if (
        case.capability_probe
        and unsupported_reason
        and result.returncode == 0
        and report is not None
    ):
        supported, status, reason = False, "unsupported", unsupported_reason
    elif case.capability_probe:
        supported = operational
        status = (
            "passed"
            if operational
            and _metrics(expected, actual)["precision"]
            == _metrics(expected, actual)["recall"]
            == 1.0
            and not case.control
            else "failed"
        )
        reason = None
    else:
        supported = source_identity_valid
        status = (
            "passed"
            if operational
            and metrics["precision"] == metrics["recall"] == 1.0
            and not (
                case.control and any(row["confidence"] in {"high", "medium"} for row in actual)
            )
            else "failed"
        )
        reason = None

    report_material = _canonical_json(report) if report is not None else ""
    evidence = {
        "interface": "fastapi-endpoint-detector analyze",
        "options": options,
        "command": command,
        "command_hash": sha_text(_canonical_json(command)),
        "exit_code": result.returncode,
        "elapsed_ms": elapsed_ms,
        "stdout": result.stdout,
        "timeout_seconds": timeout_seconds,
        "output_limit_bytes": CLI_OUTPUT_LIMIT_BYTES,
        "output_limit_exceeded": result.output_limit_exceeded,
        "timed_out": result.timed_out,
        "stdout_sha256": sha_text(result.stdout),
        "stderr": result.stderr,
        "stderr_sha256": sha_text(result.stderr),
        "report": report,
        "report_hash": sha_text(report_material) if report is not None else None,
        "parse_error": parse_error,
    }
    execution_context.record(case.case_id, evidence)
    return {
        "case_id": case.case_id,
        "symbol": case.symbol,
        "source_symbol": case.source_symbol,
        "control": case.control,
        "capability_probe": case.capability_probe,
        "change_kind": case.change_kind,
        "supported": supported,
        "status": status,
        "unsupported_reason": reason if status == "unsupported" else None,
        "expected": expected,
        "actual": actual,
        **metrics,
        "source_discovery": "secure_ast",
        "source_identity_before": identity_before,
        "source_identity_after": identity_after,
        "source_identity_valid": source_identity_valid,
        "inventory_status": inventory_status,
        "inventory_limitations": inventory_limitations,
        "total_endpoints": total_endpoints,
        "analyzer_errors": errors if isinstance(errors, list) else [str(errors)],
        "analyzer_warnings": warnings if isinstance(warnings, list) else [str(warnings)],
        "error": (
            (
                "analyzer source identity changed during this case"
                if not source_identity_valid
                else f"CLI exit {result.returncode}; {parse_error or result.stderr.strip()}"
            )
            if result.returncode != 0 or parse_error or not source_identity_valid
            else None
        ),
        "cli_evidence": evidence,
        "input_material": material,
        "input_hashes": {key: sha_text(value) for key, value in material.items()},
    }


def _sum_tier(cases: list[dict[str, Any]], tiers: set[str]) -> dict[str, Any]:
    return _tier_metrics(cases, tiers)


def run(
    output: Path, analyzer_root: Path, timeout_seconds: int = CLI_TIMEOUT_SECONDS
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    run_started = time.perf_counter()
    analyzer_root = analyzer_root.resolve()
    runner_root = Path(__file__).resolve().parents[2]
    try:
        analyzer_pin = analyzer_provenance(analyzer_root)
    except Exception as exc:
        failure = {
            "schema": SCHEMA,
            "evidence_kind": "cli_generated",
            "gate_status": "failed",
            "run_validity": "invalid",
            "integrity_errors": [f"analyzer provenance could not be pinned: {exc}"],
            "initial_source_identity": _source_identity_snapshot(analyzer_root, {}),
            "cases": [],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return failure
    execution_context = _ExecutionContext.create()
    runner_revision = _git(runner_root, "rev-parse", "HEAD")
    records = []
    with __import__("tempfile").TemporaryDirectory(prefix="typed-dag-paired-v2-") as tmp:
        fixture_root = Path(tmp)
        for case in CASES:
            material = case_inputs(case)
            try:
                record = _run_case(
                    case,
                    analyzer_root,
                    fixture_root,
                    timeout_seconds,
                    execution_context,
                    analyzer_pin["source_sha256"],
                )
            except Exception as exc:
                expected = list(expected_for(case))
                record = {
                    "case_id": case.case_id,
                    "symbol": case.symbol,
                    "source_symbol": case.source_symbol,
                    "control": case.control,
                    "capability_probe": case.capability_probe,
                    "change_kind": case.change_kind,
                    "supported": not case.capability_probe,
                    "status": "failed",
                    "unsupported_reason": None,
                    "expected": expected,
                    "actual": [],
                    **_metrics(expected, []),
                    "source_discovery": "secure_ast",
                    "inventory_status": None,
                    "inventory_limitations": [],
                    "total_endpoints": None,
                    "analyzer_errors": [str(exc)],
                    "analyzer_warnings": [],
                    "error": str(exc),
                    "cli_evidence": None,
                    "input_material": material,
                    "input_hashes": {key: sha_text(value) for key, value in material.items()},
                }
            records.append(record)

    supported = [row for row in records if row["supported"]]
    totals = {key: sum(row[key] for row in supported) for key in ("tp", "fp", "fn")}
    overall_tp = sum(row["tp"] for row in supported)
    overall_fp = sum(row["fp"] for row in supported)
    overall_fn = sum(row["fn"] for row in supported)
    overall = {
        "precision": overall_tp / (overall_tp + overall_fp)
        if overall_tp + overall_fp
        else (1.0 if overall_fn == 0 else 0.0),
        "recall": overall_tp / (overall_tp + overall_fn) if overall_tp + overall_fn else 1.0,
    }
    metrics = {
        **totals,
        "precision": overall["precision"],
        "recall": overall["recall"],
        "high_medium_control_candidates": sum(
            row["confidence"] in {"high", "medium"}
            for case in supported
            if case["control"]
            for row in case["actual"]
        ),
        "high_medium": _sum_tier(supported, {"high", "medium"}),
        "low_report_only": _sum_tier(supported, {"low"}),
    }
    coverage = {
        "declared": len(CASES),
        "recorded": len(records),
        "supported": len(supported),
        "unsupported": sum(row["status"] == "unsupported" for row in records),
        "failed": sum(row["status"] == "failed" for row in records),
    }
    gate_passed = _gate_passed(records, coverage, metrics)
    final_source_identity = _source_identity_snapshot(analyzer_root, analyzer_pin["source_sha256"])
    integrity_errors = []
    if (
        not final_source_identity["worktree_clean"]
        or final_source_identity["source_tree_hash"] != analyzer_pin["source_tree_hash"]
    ):
        integrity_errors.append(
            "analyzer source/worktree differs from its initially pinned identity"
        )
    run_validity = "valid" if not integrity_errors else "invalid"
    document = {
        "schema": SCHEMA,
        "evidence_kind": "cli_generated",
        "gate_status": "passed" if gate_passed and run_validity == "valid" else "failed",
        "run_validity": run_validity,
        "integrity_errors": integrity_errors,
        "final_source_identity": final_source_identity,
        "pass_criteria": (
            "100% precision/recall for all proven supported cases; "
            "zero HIGH/MEDIUM control candidates"
        ),
        "run_started_at": started_at,
        "run_duration_ms": round((time.perf_counter() - run_started) * 1000, 3),
        "runner_provenance": {
            "root": str(runner_root),
            "revision": runner_revision,
            "revision_hash": sha_text(runner_revision),
            "harness_sha256": sha_bytes(Path(__file__).read_bytes()),
            "fixture_generator_sha256": sha_bytes(Path(v1.__file__).read_bytes()),
            "runner_python": platform.python_version(),
            "runner_worktree_clean": not bool(
                _git(runner_root, "status", "--porcelain", "--untracked-files=all")
            ),
        },
        "analyzer_provenance": analyzer_pin,
        "configuration": {
            "backend": "mypy",
            "secure_ast": True,
            "transitive": True,
            "cache": False,
            "paired_baseline_target": True,
            "baseline_app_option_required_per_case": True,
            "case_timeout_seconds": timeout_seconds,
        },
        "configuration_hash": sha_text(
            _canonical_json(
                {
                    "backend": "mypy",
                    "secure_ast": True,
                    "transitive": True,
                    "cache": False,
                    "paired_baseline_target": True,
                    "baseline_app_option_required_per_case": True,
                    "case_timeout_seconds": timeout_seconds,
                }
            )
        ),
        "case_coverage": coverage,
        "metrics": metrics if run_validity == "valid" else None,
        "limitations": [
            "the edge oracle covers the declared generated Python call graph only",
            "original GH283 corpus, blind-release corpus, bootstrap, and "
            "incremental-performance milestones remain open",
        ],
        "unresolved_status": (
            "open: synthetic paired CLI gate is not canonical truth and does not close "
            "original GH283 milestones"
        ),
        "cases": records,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_validity == "valid":
        try:
            validate(document, analyzer_root, execution_context)
        except Exception as exc:
            document["gate_status"] = "failed"
            document["run_validity"] = "invalid"
            document["metrics"] = None
            document["integrity_errors"] = [
                *cast("list[str]", document["integrity_errors"]),
                f"generated result validation failed: {exc}",
            ]
            output.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyzer-project-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=RESULTS / "current.json")
    parser.add_argument("--timeout-seconds", type=int, default=CLI_TIMEOUT_SECONDS)
    args = parser.parse_args()
    document = run(args.output, args.analyzer_project_root, args.timeout_seconds)
    print(
        json.dumps(
            {
                "gate_status": document["gate_status"],
                "runner_revision": document["runner_provenance"]["revision"],
                "analyzer_revision": document["analyzer_provenance"]["revision"],
                "case_coverage": document["case_coverage"],
                "metrics": document["metrics"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if document["gate_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
