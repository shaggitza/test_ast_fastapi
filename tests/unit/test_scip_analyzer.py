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
