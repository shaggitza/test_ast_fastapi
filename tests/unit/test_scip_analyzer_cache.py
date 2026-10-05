from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from fastapi_endpoint_detector.analyzer.scip_analyzer import (
    SCIPAnalyzer,
    SCIPAnalyzerError,
    SCIPDefinition,
    SCIPOccurrence,
)

FIXTURE = Path("tests/fixtures/scip_controlled_project")


def _copy_fixture(destination: Path) -> None:
    shutil.copytree(FIXTURE, destination, dirs_exist_ok=True)


def _completed(payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 0, json.dumps({"result": payload}), "")


def test_module_identity_and_relative_base_import_ignore_checkout_name(tmp_path: Path) -> None:
    root = tmp_path / "arbitrary-root name"
    _copy_fixture(root)
    analyzer = SCIPAnalyzer(root)
    concrete = SCIPDefinition("impl", "pkg.impl:Impl:run()", Path("pkg/impl.py"), 5, 9)
    base = SCIPDefinition("base", "pkg.base:Base:run()", Path("pkg/base.py"), 2, 3)
    with patch.object(
        analyzer,
        "outline",
        side_effect=lambda path: (base,) if path == Path("pkg/base.py") else (),
    ):
        assert analyzer.base_method_definitions(concrete) == (base,)

    modules = analyzer._project_module_paths()
    assert modules["pkg.impl"] == Path("pkg/impl.py")
    assert modules["layout_pkg.module"] == Path("src/layout_pkg/module.py")
    assert "arbitrary-root name.pkg.impl" not in modules


@pytest.mark.parametrize(
    ("supplied", "repository_relative", "expected"),
    [
        ("pkg/impl.py", False, "pkg/impl.py"),
        ("outer/repository/pkg/impl.py", True, "pkg/impl.py"),
        (r"C:\repository\pkg\impl.py", True, "pkg/impl.py"),
        ('"pkg/impl.py"', False, "pkg/impl.py"),
    ],
)
def test_relative_paths_are_canonical_and_support_layout_spellings(
    tmp_path: Path, supplied: str, repository_relative: bool, expected: str
) -> None:
    _copy_fixture(tmp_path)
    analyzer = SCIPAnalyzer(tmp_path)
    assert (
        analyzer._relative_file(Path(supplied), repository_relative=repository_relative).as_posix()
        == expected
    )


def test_repository_relative_path_ambiguity_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "same.py").write_text("", encoding="utf-8")
    (tmp_path / "b" / "same.py").write_text("", encoding="utf-8")
    analyzer = SCIPAnalyzer(tmp_path)
    with pytest.raises(SCIPAnalyzerError, match="Ambiguous"):
        analyzer._relative_file(Path("repo/same.py"), repository_relative=True)


def test_git_c_quoted_utf8_path_decodes_to_one_canonical_file(tmp_path: Path) -> None:
    source = tmp_path / "pkg" / "café.py"
    source.parent.mkdir()
    source.write_text("value = 1\n", encoding="utf-8")
    analyzer = SCIPAnalyzer(tmp_path)
    quoted = r'"pkg/caf\303\251.py"'
    assert analyzer._relative_file(Path(quoted)).as_posix() == "pkg/café.py"


def test_cache_is_content_toolchain_addressed_and_reused_only_with_manifest(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("def app(): return 1\n", encoding="utf-8")
    analyzer = SCIPAnalyzer(tmp_path)
    versions = {"query": "0.16.0", "indexer": "0.6.6", "scip": "scip version v0.10.0"}
    analyzer._toolchain_versions = versions

    def index_result(args: list[str], *, json_output: bool = False) -> dict[str, object]:
        home = analyzer._cache_home
        assert home is not None
        index = home / "index.scip"
        index.write_bytes(b"controlled index")
        return {
            "indexPath": str(index),
            "reused": False,
            "shards": [{"command": "scip-python index --output index.scip"}],
        }

    with (
        patch.object(analyzer, "validate_tools"),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(analyzer, "_run", side_effect=index_result) as run,
    ):
        analyzer.ensure_index()
    run.assert_called_once()

    cached = SCIPAnalyzer(tmp_path)
    cached._toolchain_versions = versions
    with (
        patch.object(cached, "validate_tools"),
        patch.object(cached, "_executable", return_value="scip-query"),
        patch.object(cached, "_run", side_effect=AssertionError("verified cache should reuse")),
    ):
        cached.ensure_index()

    tool_changed = SCIPAnalyzer(tmp_path)
    tool_changed._toolchain_versions = {**versions, "scip": "scip version v0.10.1"}

    def tool_changed_index(args: list[str], *, json_output: bool = False) -> dict[str, object]:
        home = tool_changed._cache_home
        assert home is not None
        index = home / "index.scip"
        index.write_bytes(b"toolchain controlled index")
        return {
            "indexPath": str(index),
            "reused": False,
            "shards": [{"command": "scip-python index --output index.scip"}],
        }

    with (
        patch.object(tool_changed, "validate_tools"),
        patch.object(tool_changed, "_executable", return_value="scip-query"),
        patch.object(tool_changed, "_run", side_effect=tool_changed_index) as run,
    ):
        tool_changed.ensure_index()
    run.assert_called_once()

    (tmp_path / "app.py").write_text("def app(): return 2\n", encoding="utf-8")
    changed = SCIPAnalyzer(tmp_path)

    def changed_index(args: list[str], *, json_output: bool = False) -> dict[str, object]:
        home = changed._cache_home
        assert home is not None
        index = home / "index.scip"
        index.write_bytes(b"new controlled index")
        return {
            "indexPath": str(index),
            "reused": False,
            "shards": [{"command": "scip-python index --output index.scip"}],
        }

    with (
        patch.object(changed, "validate_tools"),
        patch.object(changed, "_executable", return_value="scip-query"),
        patch.object(changed, "_run", side_effect=changed_index) as run,
    ):
        changed.ensure_index()
    run.assert_called_once()


def test_inventory_deletion_and_cache_symlink_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    inventory = type("Inventory", (), {"paths": (source,)})()
    analyzer = SCIPAnalyzer(tmp_path, source_inventory=inventory)  # type: ignore[arg-type]
    source.unlink()
    with pytest.raises(SCIPAnalyzerError, match="missing path"):
        analyzer._source_manifest()

    source.write_text("value = 2\n", encoding="utf-8")
    other = tmp_path / "other.py"
    other.write_text("value = 3\n", encoding="utf-8")
    mutable_inventory = type("Inventory", (), {"paths": [source]})()
    changed_inventory = SCIPAnalyzer(tmp_path, source_inventory=mutable_inventory)  # type: ignore[arg-type]
    mutable_inventory.paths.append(other)
    with pytest.raises(SCIPAnalyzerError, match="changed after analyzer creation"):
        changed_inventory._source_manifest()

    outside = tmp_path.parent / "outside-scip-cache"
    outside.mkdir(exist_ok=True)
    cache = tmp_path / ".cache"
    cache.symlink_to(outside, target_is_directory=True)
    cache_analyzer = SCIPAnalyzer(tmp_path)
    with (
        patch.object(cache_analyzer, "validate_tools"),
        pytest.raises(SCIPAnalyzerError, match="symlink"),
    ):
        cache_analyzer.ensure_index()


def test_selected_inventory_is_explicit_but_index_manifest_covers_project_scope(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "selected.py"
    selected.write_text("value = 1\n", encoding="utf-8")
    broader = tmp_path / "outside_selection.py"
    broader.write_text("value = 2\n", encoding="utf-8")
    inventory = type("Inventory", (), {"paths": (selected,)})()
    analyzer = SCIPAnalyzer(tmp_path, source_inventory=inventory)  # type: ignore[arg-type]

    manifest = analyzer._source_manifest()
    scope = analyzer.source_scope()

    assert [record["path"] for record in manifest] == ["outside_selection.py", "selected.py"]
    assert scope.index_scope == "project_root"
    assert scope.selected_inventory_paths == ("selected.py",)
    assert any("remains project-root-wide" in item for item in scope.limitations)
    assert analyzer._inventory_configuration() is not None
    assert analyzer._inventory_configuration()["paths"] == ["selected.py"]  # type: ignore[index]

    before = {record["path"]: record["sha256"] for record in manifest}
    broader.write_text("value = 3\n", encoding="utf-8")
    after = {record["path"]: record["sha256"] for record in analyzer._source_manifest()}
    assert before["outside_selection.py"] != after["outside_selection.py"]


def test_source_hashing_rejects_file_replacement_during_read(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    replacement = tmp_path / "replacement.py"
    replacement.write_text("value = 1\n", encoding="utf-8")
    analyzer = SCIPAnalyzer(tmp_path)
    original_read = os.read
    replaced = False

    def replace_after_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        content = original_read(descriptor, size)
        if content and not replaced:
            replacement.replace(source)
            replaced = True
        return content

    with (
        patch("os.read", side_effect=replace_after_read),
        pytest.raises(SCIPAnalyzerError, match="replaced while hashing"),
    ):
        analyzer._read_source_snapshot(Path("app.py"))


def test_source_hashing_rejects_symlink_swap_during_read(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("value = 2\n", encoding="utf-8")
    link = tmp_path / "replacement.py"
    link.symlink_to(outside)
    analyzer = SCIPAnalyzer(tmp_path)
    original_read = os.read
    replaced = False

    def replace_after_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        content = original_read(descriptor, size)
        if content and not replaced:
            link.replace(source)
            replaced = True
        return content

    with (
        patch("os.read", side_effect=replace_after_read),
        pytest.raises(SCIPAnalyzerError, match="replaced while hashing"),
    ):
        analyzer._read_source_snapshot(Path("app.py"))


def test_source_hashing_fails_closed_at_per_file_limit(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("12345", encoding="utf-8")
    analyzer = SCIPAnalyzer(tmp_path)
    analyzer.MAX_SOURCE_FILE_BYTES = 4
    analyzer.MAX_SOURCE_READ_BYTES = 5
    with pytest.raises(SCIPAnalyzerError, match="per-file byte cap"):
        analyzer._read_source_snapshot(Path("app.py"))


def test_source_change_during_index_build_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    analyzer = SCIPAnalyzer(tmp_path)

    def change_source_during_index(
        args: list[str], *, json_output: bool = False
    ) -> dict[str, object]:
        home = analyzer._cache_home
        assert home is not None
        index = home / "index.scip"
        index.write_bytes(b"index from old snapshot")
        source.write_text("value = 2\n", encoding="utf-8")
        return {
            "indexPath": str(index),
            "reused": False,
            "shards": [{"command": "scip-python index --output index.scip"}],
        }

    with (
        patch.object(analyzer, "validate_tools"),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(analyzer, "_run", side_effect=change_source_during_index),
        pytest.raises(SCIPAnalyzerError, match="changed while the index was being built"),
    ):
        analyzer.ensure_index()
    assert not list(
        (tmp_path / ".cache" / "fastapi-endpoint-detector" / "scip").glob("*/provenance.json")
    )


def test_configuration_hash_changes_the_index_cache_key(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    config = tmp_path / "pyproject.toml"
    config.write_text('[project]\nname = "fixture"\nversion = "0.1.0"\n', encoding="utf-8")
    analyzer = SCIPAnalyzer(tmp_path)
    analyzer._toolchain_versions = {
        "query": "0.16.0",
        "indexer": "0.6.6",
        "scip": "0.10.0",
    }

    def index_result(owner: SCIPAnalyzer, data: bytes) -> dict[str, object]:
        home = owner._cache_home
        assert home is not None
        index = home / "index.scip"
        index.write_bytes(data)
        return {
            "indexPath": str(index),
            "reused": False,
            "shards": [{"command": "scip-python index --output index.scip"}],
        }

    def first_result(args: list[str], *, json_output: bool = False) -> dict[str, object]:
        assert args[1] == "reindex" and json_output
        return index_result(analyzer, b"first")

    def second_result(args: list[str], *, json_output: bool = False) -> dict[str, object]:
        assert args[1] == "reindex" and json_output
        return index_result(changed, b"second")

    with (
        patch.object(analyzer, "validate_tools"),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(analyzer, "_run", side_effect=first_result),
    ):
        analyzer.ensure_index()
    config.write_text('[project]\nname = "fixture"\nversion = "0.2.0"\n', encoding="utf-8")
    changed = SCIPAnalyzer(tmp_path)
    changed._toolchain_versions = analyzer._toolchain_versions
    with (
        patch.object(changed, "validate_tools"),
        patch.object(changed, "_executable", return_value="scip-query"),
        patch.object(changed, "_run", side_effect=second_result) as run,
    ):
        changed.ensure_index()
    run.assert_called_once()
    assert changed._active_index != analyzer._active_index


def test_disabled_cache_does_not_publish_a_reusable_manifest(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    analyzer = SCIPAnalyzer(tmp_path, use_cache=False)

    def build_index(args: list[str], *, json_output: bool = False) -> dict[str, object]:
        assert args[1] == "reindex" and json_output
        assert analyzer._cache_home is not None
        index = analyzer._cache_home / "index.scip"
        index.write_bytes(b"no-cache index")
        return {
            "indexPath": str(index),
            "reused": False,
            "shards": [{"command": "scip-python index --output index.scip"}],
        }

    with (
        patch.object(analyzer, "validate_tools"),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(analyzer, "_run", side_effect=build_index),
    ):
        analyzer.ensure_index()
    assert not list(
        (tmp_path / ".cache" / "fastapi-endpoint-detector" / "scip").glob("*/provenance.json")
    )


def test_aliased_reference_resolves_to_innermost_nested_callable(tmp_path: Path) -> None:
    (tmp_path / "callee.py").write_text("def target(): ...\n", encoding="utf-8")
    caller_source = tmp_path / "caller.py"
    caller_source.write_text(
        "from callee import target as invoke\n"
        "def outer():\n"
        "    def nested():\n"
        "        invoke()\n"
        "    nested()\n",
        encoding="utf-8",
    )
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition("target", "callee:target()", Path("callee.py"), 1, 1)
    outer = SCIPDefinition("outer", "caller:outer()", Path("caller.py"), 2, 5)
    nested = SCIPDefinition("nested", "caller:outer:nested()", Path("caller.py"), 3, 4)
    payload = {
        "matched": True,
        "resolved": {
            "symbol": callee.symbol,
            "shortName": callee.short_name,
            "relativePath": "callee.py",
        },
        "otherMatches": [],
        "totalMatches": 1,
        "references": [{"relativePath": "caller.py", "line": 3}],
    }
    with (
        patch.object(analyzer, "_run", return_value=payload),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(analyzer, "outline", return_value=(outer, nested)),
    ):
        edges = analyzer.reverse_call_edges(callee)
    assert len(edges) == 1
    assert edges[0].caller == nested
    assert edges[0].callee == callee
    assert edges[0].occurrence == SCIPOccurrence(Path("caller.py"), 4)
    assert edges[0].execution_status == "reference_only"
    assert edges[0].confidence == "LOW"


def test_multiple_same_line_calls_remain_unresolved(tmp_path: Path) -> None:
    (tmp_path / "callee.py").write_text("def target(): ...\n", encoding="utf-8")
    (tmp_path / "caller.py").write_text(
        "from callee import target\ndef caller():\n    target(); target()\n",
        encoding="utf-8",
    )
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition("target", "callee:target()", Path("callee.py"), 1, 1)
    caller = SCIPDefinition("caller", "caller:caller()", Path("caller.py"), 2, 3)
    payload = {
        "matched": True,
        "resolved": {
            "symbol": callee.symbol,
            "shortName": callee.short_name,
            "relativePath": "callee.py",
        },
        "otherMatches": [],
        "totalMatches": 1,
        "references": [{"relativePath": "caller.py", "line": 2}],
    }
    with (
        patch.object(analyzer, "_run", return_value=payload),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(analyzer, "outline", return_value=(caller,)),
    ):
        assert analyzer.reverse_call_edges(callee) == ()


def test_reference_to_import_binding_is_reported_as_unsupported_not_a_call(
    tmp_path: Path,
) -> None:
    (tmp_path / "callee.py").write_text("def target(): ...\n", encoding="utf-8")
    (tmp_path / "caller.py").write_text(
        "from callee import target as invoke\ndef caller():\n    invoke()\n",
        encoding="utf-8",
    )
    analyzer = SCIPAnalyzer(tmp_path)
    callee = SCIPDefinition("target", "callee:target()", Path("callee.py"), 1, 1)
    payload = {
        "matched": True,
        "resolved": {
            "symbol": callee.symbol,
            "shortName": callee.short_name,
            "relativePath": "callee.py",
        },
        "otherMatches": [],
        "totalMatches": 1,
        "references": [{"relativePath": "caller.py", "line": 0}],
    }
    with (
        patch.object(analyzer, "_run", return_value=payload),
        patch.object(analyzer, "_executable", return_value="scip-query"),
    ):
        assert analyzer.reverse_call_edges(callee) == ()
    assert analyzer.reverse_call_edge_limitations(callee)
