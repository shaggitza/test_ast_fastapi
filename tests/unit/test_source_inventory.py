"""Tests for canonical source scoping and explicit unresolved changes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper, ChangeMapperError
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.config import Config, ParserConfig
from fastapi_endpoint_detector.models.endpoint import InventoryStatus
from fastapi_endpoint_detector.parser.diff_parser import DiffParser
from fastapi_endpoint_detector.parser.secure_ast_extractor import SecureASTExtractor
from fastapi_endpoint_detector.source_inventory import SourceInventory, SourceInventoryError


def test_inventory_is_deterministic_and_applies_project_relative_globs(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "main.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "pkg" / "worker.py").write_text("value = 2\n", encoding="utf-8")
    (tmp_path / "pkg" / "ignored.py").write_text("value = 3\n", encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text("value = 4\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("docs\n", encoding="utf-8")

    first = SourceInventory.build(
        tmp_path,
        include_patterns=("**/*.py", "README.md"),
        exclude_patterns=("**/ignored.py", "**/tests/**"),
    )
    second = SourceInventory.build(
        tmp_path,
        include_patterns=("**/*.py", "README.md"),
        exclude_patterns=("**/ignored.py", "**/tests/**"),
    )

    assert [item.relative_path for item in first.entries] == [
        "README.md",
        "main.py",
        "pkg/worker.py",
    ]
    assert [item.module_name for item in first.python_entries] == ["main", "pkg.worker"]
    assert first == second
    assert first.fingerprint == second.fingerprint


def test_inventory_detects_source_drift_atomically(tmp_path: Path) -> None:
    source = tmp_path / "main.py"
    source.write_text("value = 1\n", encoding="utf-8")
    inventory = SourceInventory.build(tmp_path)
    source.write_text("value = 2\n", encoding="utf-8")

    with pytest.raises(SourceInventoryError, match="changed after snapshot"):
        inventory.verify()
    extracted = SecureASTExtractor(tmp_path, source_inventory=inventory).extract_inventory()
    assert extracted.status == InventoryStatus.UNAVAILABLE
    assert "could not be verified" in extracted.limitations[0].reason


def test_secure_ast_and_mypy_consume_the_same_inventory(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/kept')\ndef kept(): pass\n",
        encoding="utf-8",
    )
    (tmp_path / "excluded.py").write_text("this is invalid Python !!!\n", encoding="utf-8")
    inventory = SourceInventory.build(
        tmp_path,
        include_patterns=("main.py",),
        exclude_patterns=(),
    )

    extracted = SecureASTExtractor(tmp_path, source_inventory=inventory).extract_inventory()
    analyzer = MypyAnalyzer(tmp_path, source_inventory=inventory)
    _fingerprint, sources = analyzer._cache_fingerprint()

    assert extracted.status == InventoryStatus.ESTABLISHED
    assert [endpoint.identifier for endpoint in extracted.endpoints] == ["GET /kept"]
    assert sources == {"main.py": inventory.python_entries[0].sha256}


@pytest.mark.parametrize(
    "data, message",
    [
        ({"parser": {"follow_imports": False}}, "follow_imports"),
        ({"analysis": {"include_test_endpoints": True}}, "include_test_endpoints"),
        ({"integrations": {"use_mypy": False}}, "use_mypy"),
        ({"integrations": {"mypy_config": "mypy.ini"}}, "mypy_config"),
    ],
)
def test_ignored_nondefault_controls_are_rejected(data: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Config.model_validate(data)


def test_change_mapper_shares_one_inventory_between_ast_and_mypy(tmp_path: Path) -> None:
    app = tmp_path / "main.py"
    app.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    mapper = ChangeMapper(app, secure_ast=True)

    assert mapper.extractor.source_inventory is mapper.source_inventory
    assert mapper.mypy_analyzer.source_inventory is mapper.source_inventory


def test_runtime_and_scip_reject_custom_source_scope(tmp_path: Path) -> None:
    app = tmp_path / "main.py"
    app.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    config = Config(parser=ParserConfig(include_patterns=["main.py"], exclude_patterns=[]))

    with pytest.raises(ChangeMapperError, match="require secure_ast"):
        ChangeMapper(app, config=config)
    with pytest.raises(ChangeMapperError, match="unsupported by SCIP"):
        ChangeMapper(app, config=config, secure_ast=True, use_scip=True)


def test_non_python_and_out_of_scope_python_changes_are_explicit(tmp_path: Path) -> None:
    app = tmp_path / "main.py"
    app.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    config = Config(parser=ParserConfig(include_patterns=["main.py"], exclude_patterns=[]))
    mapper = ChangeMapper(app, config=config, secure_ast=True)
    diff_files = DiffParser.parse_string(
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
        "diff --git a/other.py b/other.py\n"
        "--- a/other.py\n"
        "+++ b/other.py\n"
        "@@ -1 +1 @@\n"
        "-old = 1\n"
        "+new = 2\n"
    )

    in_scope, all_python, unresolved = mapper._partition_changed_files(diff_files)

    assert in_scope == []
    assert [item.path.as_posix() for item in all_python] == ["other.py"]
    assert [(item.file_path, item.reason) for item in unresolved] == [
        (
            "README.md",
            "Unsupported non-Python/configuration change; "
            "no finite dependency contract is configured",
        ),
        ("other.py", "Python change is outside the configured canonical source inventory"),
    ]
    assert all(item.total_lines == 2 for item in unresolved)


def test_non_python_change_survives_into_report(tmp_path: Path) -> None:
    app = tmp_path / "main.py"
    app.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    mapper = ChangeMapper(app, secure_ast=True, use_cache=False)

    report = mapper.analyze_diff(
        "diff --git a/deploy.yaml b/deploy.yaml\n"
        "--- a/deploy.yaml\n"
        "+++ b/deploy.yaml\n"
        "@@ -1 +1 @@\n"
        "-replicas: 1\n"
        "+replicas: 2\n"
    )

    assert report.total_files_changed == 1
    assert report.python_files_changed == 0
    assert len(report.orphan_changes) == 1
    assert report.orphan_changes[0].file_path == "deploy.yaml"
    assert "Unsupported non-Python/configuration change" in report.orphan_changes[0].reason
