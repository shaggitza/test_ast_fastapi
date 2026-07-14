from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from fastapi_endpoint_detector.analyzer.scip_analyzer import (
    SCIPAnalyzer,
    SCIPAnalyzerError,
    SCIPDefinition,
    SCIPOccurrence,
    SCIPReverseCallEdge,
)


def completed(
    stdout: str = "", *, code: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, stdout, stderr)


def test_outline_converts_zero_based_ranges_and_selects_narrowest(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    payload = {
        "result": [
            {
                "symbol": "outer",
                "shortName": "m:outer()",
                "startLine": 0,
                "endLine": 10,
                "children": [
                    {
                        "symbol": "inner",
                        "shortName": "m:inner()",
                        "startLine": 4,
                        "endLine": 5,
                    }
                ],
            },
        ]
    }
    with (
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch("subprocess.run", return_value=completed(json.dumps(payload))),
    ):
        definitions = analyzer.definitions_at(Path("module.py"), {5})

    assert definitions == (SCIPDefinition("inner", "m:inner()", Path("module.py"), 5, 6),)


def test_affected_resolves_returned_functions_through_file_outline(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    seed = SCIPDefinition("seed", "services:changed()", Path("services.py"), 1, 2)

    def fake_run(args: list[str], *, json_output: bool = False):
        if "affected" in args:
            return {
                "matched": True,
                "resolved": {"symbol": "seed"},
                "totalMatches": 1,
                "affected": [{"shortName": "main:handler()", "file": "main.py", "depth": 2}],
            }
        return [{"symbol": "handler", "shortName": "main:handler()", "startLine": 6, "endLine": 8}]

    with (
        patch.object(analyzer, "_run", side_effect=fake_run),
        patch.object(analyzer, "_executable", return_value="scip-query"),
    ):
        reached = analyzer.affected(seed)

    assert reached[0].definition == seed
    assert reached[1].definition.symbol == "handler"
    assert reached[1].definition.start_line == 7
    assert reached[1].depth == 2


def test_ast_extends_truncated_scip_callable_range(tmp_path: Path) -> None:
    source = tmp_path / "module.py"
    source.write_text("def changed():\n    value = 1\n    value += 1\n    return value\n")
    analyzer = SCIPAnalyzer(tmp_path)
    with (
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(
            analyzer,
            "_run",
            return_value=[
                {
                    "symbol": "changed",
                    "shortName": "module:changed()",
                    "startLine": 0,
                    "endLine": 1,
                }
            ],
        ),
    ):
        definitions = analyzer.definitions_at(source, {4})

    assert definitions[0].symbol == "changed"
    assert definitions[0].end_line == 4


def test_resolves_explicit_inherited_base_method(tmp_path: Path) -> None:
    (tmp_path / "base.py").write_text(
        "class Base:\n    def run(self):\n        raise NotImplementedError\n"
    )
    (tmp_path / "impl.py").write_text(
        "from base import Base\n\nclass Impl(Base):\n    def run(self):\n        return 1\n"
    )
    analyzer = SCIPAnalyzer(tmp_path)
    concrete = SCIPDefinition("impl-symbol", "impl:Impl:run()", Path("impl.py"), 4, 5)
    base = SCIPDefinition("base-symbol", "base:Base:run()", Path("base.py"), 2, 3)
    with patch.object(
        analyzer,
        "outline",
        side_effect=lambda path: (base,) if path == Path("base.py") else (),
    ):
        related = analyzer.base_method_definitions(concrete)

    assert related == (base,)


@pytest.mark.parametrize(
    ("source", "extra_files"),
    [
        (
            "class Unrelated:\n"
            "    def run(self):\n"
            "        return 0\n\n"
            "class Impl:\n"
            "    def run(self):\n"
            "        return 1\n",
            {},
        ),
        (
            "from first import Base\n"
            "from second import Base\n\n"
            "class Impl(Base):\n"
            "    def run(self):\n"
            "        return 1\n",
            {
                "first.py": "class Base:\n    def run(self): ...\n",
                "second.py": "class Base:\n    def run(self): ...\n",
            },
        ),
        (
            "def base_factory():\n"
            "    return object\n\n"
            "class Impl(base_factory()):\n"
            "    def run(self):\n"
            "        return 1\n",
            {},
        ),
        (
            "from missing_package import Base\n\n"
            "class Impl(Base):\n"
            "    def run(self):\n"
            "        return 1\n",
            {},
        ),
    ],
    ids=["unrelated-same-name", "ambiguous-import", "computed-base", "unresolved-import"],
)
def test_base_method_resolution_fails_closed(
    tmp_path: Path, source: str, extra_files: dict[str, str]
) -> None:
    (tmp_path / "impl.py").write_text(source)
    for name, content in extra_files.items():
        (tmp_path / name).write_text(content)
    analyzer = SCIPAnalyzer(tmp_path)
    concrete = SCIPDefinition("impl-symbol", "impl:Impl:run()", Path("impl.py"), 5, 6)

    assert analyzer.base_method_definitions(concrete) == ()


def test_affected_rejects_wrong_or_ambiguous_seed_resolution(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    seed = SCIPDefinition("exact", "module:changed()", Path("module.py"), 1, 2)
    with (
        patch.object(
            analyzer,
            "_run",
            return_value={
                "matched": True,
                "resolved": {"symbol": "wrong"},
                "totalMatches": 200,
                "affected": [],
            },
        ),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        pytest.raises(SCIPAnalyzerError, match="wrong seed"),
    ):
        analyzer.affected(seed)


def test_validate_tools_rejects_plus_indexer(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    with (
        patch("shutil.which", return_value="/bin/tool"),
        pytest.raises(SCIPAnalyzerError, match="scip-python-plus"),
    ):
        analyzer.validate_tools()


def test_reindex_rejects_unverified_cached_or_plus_provenance(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    with (
        patch.object(analyzer, "validate_tools"),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(
            analyzer,
            "_run",
            return_value={
                "indexPath": "/tmp/index.scip",
                "reused": False,
                "shards": [{"command": "scip-python-plus index --output index.scip"}],
            },
        ),
        pytest.raises(SCIPAnalyzerError, match="provenance"),
    ):
        analyzer.ensure_index()


def test_command_failure_is_explicit(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    with (
        patch("subprocess.run", return_value=completed(code=7, stderr="broken index")),
        pytest.raises(SCIPAnalyzerError, match="broken index"),
    ):
        analyzer._run(["scip-query", "outline", "x.py", "--json"], json_output=True)


def test_reverse_call_edges_proves_calls_deduplicates_sorts_and_caches(tmp_path: Path) -> None:
    (tmp_path / "callee.py").write_text("def target():\n    return None\n")
    (tmp_path / "z.py").write_text(
        "def z_caller():\n"
        "    target()\n"
        "    value = target\n"
        "target()\n"
        "def ambiguous():\n"
        "    target(); target()\n"
        "def outer():\n"
        "    def nested():\n"
        "        target()\n"
    )
    (tmp_path / "a.py").write_text("async def a_caller():\n    await target()\n")
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition("full target symbol", "callee:target()", Path("callee.py"), 1, 2)
    z_caller = SCIPDefinition("z symbol", "z:z_caller()", Path("z.py"), 1, 3)
    a_caller = SCIPDefinition("a symbol", "a:a_caller()", Path("a.py"), 1, 2)
    payload = {
        "matched": True,
        "resolved": {
            "symbol": callee.symbol,
            "shortName": callee.short_name,
            "relativePath": "callee.py",
        },
        "otherMatches": [],
        "totalMatches": 1,
        "references": [
            {"relativePath": "z.py", "line": 1},
            {"relativePath": "z.py", "line": 2},
            {"relativePath": "z.py", "line": 3},
            {"relativePath": "z.py", "line": 5},
            {"relativePath": "z.py", "line": 8},
            {"relativePath": "z.py", "line": 1},
            {"relativePath": "a.py", "line": 1},
        ],
    }

    with (
        patch.object(analyzer, "_run", return_value=payload) as run,
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(
            analyzer,
            "outline",
            side_effect=lambda path: (a_caller,) if path == Path("a.py") else (z_caller,),
        ),
    ):
        first = analyzer.reverse_call_edges(callee)
        second = analyzer.reverse_call_edges(callee)

    assert first == (
        SCIPReverseCallEdge(a_caller, callee, SCIPOccurrence(Path("a.py"), 2)),
        SCIPReverseCallEdge(z_caller, callee, SCIPOccurrence(Path("z.py"), 2)),
    )
    assert second is first
    run.assert_called_once_with(["scip-query", "refs", callee.symbol, "--json"], json_output=True)


def test_reverse_call_edges_rejects_reference_lines_without_callee_call(
    tmp_path: Path,
) -> None:
    (tmp_path / "callee.py").write_text("def target(): ...\n")
    (tmp_path / "caller.py").write_text(
        "def caller():\n"
        "    consume(target)\n"
        "    alias = target; other()\n"
        "    alias = target; other.target()\n"
    )
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition("target", "callee:target()", Path("callee.py"), 1, 1)
    caller = SCIPDefinition("caller", "caller:caller()", Path("caller.py"), 1, 4)
    payload = {
        "matched": True,
        "resolved": {
            "symbol": "target",
            "shortName": "callee:target()",
            "relativePath": "callee.py",
        },
        "otherMatches": [],
        "totalMatches": 1,
        "references": [
            {"relativePath": "caller.py", "line": 1},
            {"relativePath": "caller.py", "line": 2},
            {"relativePath": "caller.py", "line": 3},
        ],
    }
    with (
        patch.object(analyzer, "_run", return_value=payload),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(analyzer, "outline", return_value=(caller,)),
    ):
        assert analyzer.reverse_call_edges(callee) == ()


@pytest.mark.parametrize(
    ("resolved_symbol", "total_matches", "message"),
    [
        ("wrong", 1, "wrong refs seed"),
        ("full target symbol", 2, "ambiguous"),
        ("full target symbol", True, "ambiguous"),
    ],
)
def test_reverse_call_edges_requires_unique_exact_full_symbol(
    tmp_path: Path, resolved_symbol: str, total_matches: object, message: str
) -> None:
    (tmp_path / "callee.py").write_text("def target(): ...\n")
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition("full target symbol", "callee:target()", Path("callee.py"), 1, 1)
    payload = {
        "matched": True,
        "resolved": {
            "symbol": resolved_symbol,
            "shortName": "callee:target()",
            "relativePath": "callee.py",
        },
        "otherMatches": [],
        "totalMatches": total_matches,
        "references": [],
    }
    with (
        patch.object(analyzer, "_run", return_value=payload),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        pytest.raises(SCIPAnalyzerError, match=message),
    ):
        analyzer.reverse_call_edges(callee)


@pytest.mark.parametrize(
    ("resolved_short_name", "resolved_path", "message"),
    [
        ("other:target()", "callee.py", "inconsistent short name"),
        ("callee:target()", "other.py", "inconsistent definition path"),
    ],
)
def test_reverse_call_edges_rejects_inconsistent_resolution_metadata(
    tmp_path: Path, resolved_short_name: str, resolved_path: str, message: str
) -> None:
    (tmp_path / "callee.py").write_text("def target(): ...\n")
    (tmp_path / "other.py").write_text("def target(): ...\n")
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition("target", "callee:target()", Path("callee.py"), 1, 1)
    payload = {
        "matched": True,
        "resolved": {
            "symbol": "target",
            "shortName": resolved_short_name,
            "relativePath": resolved_path,
        },
        "otherMatches": [],
        "totalMatches": 1,
        "references": [],
    }
    with (
        patch.object(analyzer, "_run", return_value=payload),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        pytest.raises(SCIPAnalyzerError, match=message),
    ):
        analyzer.reverse_call_edges(callee)


@pytest.mark.parametrize(
    "reference",
    [
        {"relativePath": "../outside.py", "line": 0},
        {"relativePath": "/outside.py", "line": 0},
        {"relativePath": "caller.py", "line": -1},
        {"relativePath": "caller.py", "line": True},
        {"relativePath": "caller.py"},
    ],
)
def test_reverse_call_edges_rejects_malformed_or_outside_references(
    tmp_path: Path, reference: dict[str, object]
) -> None:
    (tmp_path / "callee.py").write_text("def target(): ...\n")
    (tmp_path / "caller.py").write_text("def caller():\n    target()\n")
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition("target", "callee:target()", Path("callee.py"), 1, 1)
    payload = {
        "matched": True,
        "resolved": {
            "symbol": "target",
            "shortName": "callee:target()",
            "relativePath": "callee.py",
        },
        "otherMatches": [],
        "totalMatches": 1,
        "references": [reference],
    }
    with (
        patch.object(analyzer, "_run", return_value=payload),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        pytest.raises(SCIPAnalyzerError),
    ):
        analyzer.reverse_call_edges(callee)


def test_reverse_call_edges_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.py"
    outside.write_text("def caller():\n    target()\n")
    (tmp_path / "callee.py").write_text("def target(): ...\n")
    (tmp_path / "escape.py").symlink_to(outside)
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition("target", "callee:target()", Path("callee.py"), 1, 1)
    payload = {
        "matched": True,
        "resolved": {
            "symbol": "target",
            "shortName": "callee:target()",
            "relativePath": "callee.py",
        },
        "otherMatches": [],
        "totalMatches": 1,
        "references": [{"relativePath": "escape.py", "line": 1}],
    }
    with (
        patch.object(analyzer, "_run", return_value=payload),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        pytest.raises(SCIPAnalyzerError, match="Invalid SCIP reference path"),
    ):
        analyzer.reverse_call_edges(callee)


def test_reverse_call_edges_uses_sanitized_pinned_schema_and_argv(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/scip_refs_0_16_0.json")
    payload = fixture.read_text(encoding="utf-8")
    (tmp_path / "services.py").write_text("def calculate():\n    return 1\n")
    (tmp_path / "routers.py").write_text(
        "def quote():\n    value = 1\n    value += 1\n    return calculate()\n"
    )
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition(
        "scip-python python fixture 0.0.0 `services`/calculate().",
        "services:calculate()",
        Path("services.py"),
        1,
        2,
    )
    caller = SCIPDefinition(
        "scip-python python fixture 0.0.0 `routers`/quote().",
        "routers:quote()",
        Path("routers.py"),
        1,
        4,
    )
    with (
        patch.object(analyzer, "_executable", return_value="/tools/scip-query"),
        patch("subprocess.run", return_value=completed(payload)) as run,
        patch.object(analyzer, "outline", return_value=(caller,)),
    ):
        edges = analyzer.reverse_call_edges(callee)

    assert edges == (SCIPReverseCallEdge(caller, callee, SCIPOccurrence(Path("routers.py"), 4)),)
    argv = run.call_args.args[0]
    assert argv == ["/tools/scip-query", "refs", callee.symbol, "--json"]
    assert "shell" not in run.call_args.kwargs
