"""Tests for canonical source scoping and explicit unresolved changes."""

from __future__ import annotations

from pathlib import Path

import pytest

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


def test_segment_globs_match_zero_and_multiple_directory_depths(tmp_path: Path) -> None:
    for relative in (
        "pkg/main.py",
        "pkg/deep/nested/worker.py",
        "tests/helper.py",
        "tests/deep/helper.py",
        "pkg/tests/helper.py",
        "pkg/tests/deep/helper.py",
    ):
        source = tmp_path / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("value = 1\n", encoding="utf-8")

    inventory = SourceInventory.build(
        tmp_path,
        include_patterns=("pkg/**/*.py",),
        exclude_patterns=("**/tests/**",),
    )

    assert [entry.relative_path for entry in inventory.entries] == [
        "pkg/deep/nested/worker.py",
        "pkg/main.py",
    ]


def test_diff_scope_rejects_absolute_traversal_and_ambiguous_paths(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("value = 1\n", encoding="utf-8")
    inventory = SourceInventory.build(
        tmp_path,
        include_patterns=("main.py",),
        exclude_patterns=(),
    )

    assert inventory.allows_diff_path(Path("main.py"))
    assert not inventory.allows_diff_path(Path("a/main.py"))
    assert not inventory.allows_diff_path(Path("b/main.py"))
    for unsafe in (
        Path("/etc/outside.py"),
        Path("../outside.py"),
        Path("a/../outside.py"),
        Path("b/../../outside.py"),
        Path("C:\\outside.py"),
    ):
        assert not inventory.allows_diff_path(unsafe)


def test_rename_scope_authenticates_both_sides_without_traversal(tmp_path: Path) -> None:
    app = tmp_path / "main.py"
    app.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    mapper = ChangeMapper(app, secure_ast=True)
    safe_rename = DiffParser.parse_string(
        "diff --git a/old.py b/new.txt\n"
        "similarity index 100%\n"
        "rename from old.py\n"
        "rename to new.txt\n"
    )
    unsafe_rename = DiffParser.parse_string(
        "diff --git a/../outside.py b/new.txt\n"
        "similarity index 100%\n"
        "rename from ../outside.py\n"
        "rename to new.txt\n"
    )

    safe_scope, _, safe_unresolved = mapper._partition_changed_files(safe_rename)
    unsafe_scope, _, unsafe_unresolved = mapper._partition_changed_files(unsafe_rename)

    assert safe_scope == safe_rename
    assert safe_unresolved == []
    assert unsafe_scope == []
    assert len(unsafe_unresolved) == 1


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


def test_inventory_caps_accept_boundaries_and_reject_overflow(tmp_path: Path) -> None:
    hidden = tmp_path / ".ignored"
    hidden.mkdir()
    for index in range(10):
        (hidden / f"ignored-{index}.py").write_text("ignored", encoding="utf-8")
    first = tmp_path / "a.py"
    first.write_bytes(b"ab")

    boundary = SourceInventory.build(
        tmp_path,
        max_candidates=2,
        max_files=1,
        max_file_bytes=2,
        max_aggregate_bytes=2,
    )
    assert [(entry.relative_path, entry.size_bytes) for entry in boundary.entries] == [
        ("a.py", 2)
    ]

    with pytest.raises(SourceInventoryError, match="candidate limit"):
        SourceInventory.build(tmp_path, max_candidates=1)
    with pytest.raises(SourceInventoryError, match="per-file byte limit"):
        SourceInventory.build(tmp_path, max_file_bytes=1)

    second = tmp_path / "b.py"
    second.write_bytes(b"cd")
    with pytest.raises(SourceInventoryError, match="selected-file limit"):
        SourceInventory.build(tmp_path, max_files=1)
    aggregate_boundary = SourceInventory.build(tmp_path, max_aggregate_bytes=4)
    assert sum(entry.size_bytes for entry in aggregate_boundary.entries) == 4
    with pytest.raises(SourceInventoryError, match="aggregate byte limit"):
        SourceInventory.build(tmp_path, max_aggregate_bytes=3)


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


def _mapper_with_excluded_import(tmp_path: Path) -> ChangeMapper:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from pkg.helper import value\n"
        "app = FastAPI()\n"
        "@app.get('/')\n"
        "def handler() -> int:\n"
        "    return value\n",
        encoding="utf-8",
    )
    config = Config(
        parser=ParserConfig(
            include_patterns=["pkg/__init__.py", "pkg/main.py"],
            exclude_patterns=[],
        )
    )
    return ChangeMapper(tmp_path, config=config, secure_ast=True)


def test_change_mapper_authenticates_graph_before_loading_valid_cache(tmp_path: Path) -> None:
    seeded = _mapper_with_excluded_import(tmp_path)
    seeded._preanalyze_mypy()
    assert seeded.mypy_analyzer.cache_path.exists()
    assert seeded.mypy_analyzer.get_endpoint_dependencies(seeded.registry.get_all()[0]) is not None

    (tmp_path / "pkg" / "helper.py").write_text("value = 1\n", encoding="utf-8")
    fresh = ChangeMapper(tmp_path, config=seeded.config, secure_ast=True)

    with pytest.raises(SourceInventoryError, match="graph inputs absent"):
        fresh._preanalyze_mypy()

    assert fresh.mypy_analyzer._build_result is None
    assert fresh.mypy_analyzer._trees == {}


def test_change_mapper_reauthenticates_graph_before_same_analyzer_cache_reuse(
    tmp_path: Path,
) -> None:
    mapper = _mapper_with_excluded_import(tmp_path)
    mapper._preanalyze_mypy()
    assert mapper.mypy_analyzer._build_result is not None
    assert mapper.mypy_analyzer._trees

    (tmp_path / "pkg" / "helper.py").write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(SourceInventoryError, match="graph inputs absent"):
        mapper._preanalyze_mypy()

    assert mapper.mypy_analyzer._build_result is None
    assert mapper.mypy_analyzer._trees == {}


def test_mypy_fails_closed_before_cache_for_excluded_project_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text("from pkg.helper import value\n", encoding="utf-8")
    inventory = SourceInventory.build(
        tmp_path,
        include_patterns=("pkg/__init__.py", "pkg/main.py"),
        exclude_patterns=(),
    )
    analyzer = MypyAnalyzer(package, source_inventory=inventory)
    initial_fingerprint = analyzer._cache_fingerprint()[0]
    analyzer._ensure_mypy_built()  # Missing imports are external/unknown, not local inputs.

    helper = package / "helper.py"
    helper.write_text("value = 1\n", encoding="utf-8")
    assert analyzer._cache_fingerprint()[0] == initial_fingerprint

    cached = MypyAnalyzer(package, source_inventory=inventory)
    cached.set_cache_path(tmp_path / "cache.json")
    cached.cache_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cached, "_load_cache", lambda: True)
    with pytest.raises(SourceInventoryError, match="graph inputs absent"):
        cached.analyze_endpoints([], use_cache=True)
    assert cached._build_result is None
    assert cached._trees == {}

    helper.write_text("value = 2\n", encoding="utf-8")
    with pytest.raises(SourceInventoryError, match="graph inputs absent"):
        cached._ensure_mypy_built()


def test_shared_inventory_canonicalizes_mypy_build_root_context(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text("value = 1\n", encoding="utf-8")
    inventory = SourceInventory.build(tmp_path)

    project_analyzer = MypyAnalyzer(tmp_path, source_inventory=inventory)
    package_analyzer = MypyAnalyzer(package, source_inventory=inventory)

    assert project_analyzer.cache_path == package_analyzer.cache_path
    assert project_analyzer._get_source_root() != package_analyzer._get_source_root()
    # Build sources, mypy_path, module names, and the cache identity all use the
    # inventory root, so app-path forms cannot collide with differing contexts.
    assert project_analyzer._cache_fingerprint()[0] == package_analyzer._cache_fingerprint()[0]


@pytest.mark.parametrize("pattern", ["C:/outside.py", "C:\\outside.py"])
@pytest.mark.parametrize("field_name", ["include_patterns", "exclude_patterns"])
def test_windows_drive_absolute_source_globs_are_rejected(
    field_name: str, pattern: str
) -> None:
    values = {field_name: [pattern]}
    with pytest.raises(ValueError, match="project-relative globs"):
        ParserConfig.model_validate(values)


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
