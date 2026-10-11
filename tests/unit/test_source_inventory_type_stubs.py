"""Type declarations must never silently become executable source scope."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from fastapi_endpoint_detector.analyzer.source_inventory import build_source_inventory

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("with_runtime_source", [False, True])
def test_imported_local_type_stub_is_explicitly_unresolved(
    tmp_path: Path, with_runtime_source: bool
) -> None:
    (tmp_path / "main.py").write_text("from helper import emit\n", encoding="utf-8")
    (tmp_path / "helper.pyi").write_text("def emit(resource: str) -> int: ...\n", encoding="utf-8")
    if with_runtime_source:
        (tmp_path / "helper.py").write_text(
            "def emit(resource: str) -> int:\n    return 1\n", encoding="utf-8"
        )

    inventory = build_source_inventory(tmp_path)

    assert all(path.suffix == ".py" for path in inventory.paths)
    assert (tmp_path / "helper.pyi") not in inventory.paths
    assert ("main.py", "helper.emit") in inventory.unresolved_imports
    assert any("type stub helper.pyi" in item for item in inventory.limitations)
    assert inventory.module_collisions == ()
    if with_runtime_source:
        assert (tmp_path / "helper.py") in inventory.paths


@pytest.mark.parametrize("pattern", ["**/*.pyi", "**/*"])
def test_selected_stub_is_a_limitation_and_never_an_executable_source(
    tmp_path: Path, pattern: str
) -> None:
    (tmp_path / "helper.pyi").write_text("def emit(resource: str) -> int: ...\n", encoding="utf-8")

    inventory = build_source_inventory(tmp_path, include_patterns=(pattern,))

    assert inventory.files == ()
    assert inventory.paths == ()
    assert any("Selected type stub helper.pyi" in item for item in inventory.limitations)


def test_unrelated_or_excluded_stub_does_not_broaden_runtime_census(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "helper.pyi").write_text("value: int\n", encoding="utf-8")

    default = build_source_inventory(tmp_path)
    excluded = build_source_inventory(
        tmp_path, include_patterns=("**/*",), exclude_patterns=("helper.pyi",)
    )

    assert default.paths == excluded.paths == (tmp_path / "main.py",)
    assert default.limitations == excluded.limitations == ()
    assert default.unresolved_imports == excluded.unresolved_imports == ()


def test_excluded_stub_can_still_affect_a_selected_import(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("from helper import emit\n", encoding="utf-8")
    (tmp_path / "helper.pyi").write_text("def emit(resource: str) -> int: ...\n", encoding="utf-8")

    inventory = build_source_inventory(tmp_path, exclude_patterns=("helper.pyi",))

    assert inventory.paths == (tmp_path / "main.py",)
    assert ("main.py", "helper.emit") in inventory.unresolved_imports
    assert any("type stub helper.pyi" in item for item in inventory.limitations)
    assert not any("Selected type stub" in item for item in inventory.limitations)


def test_root_stub_initializer_has_explicit_static_identity_limitation(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "__init__.pyi").write_text("value: int\n", encoding="utf-8")

    inventory = build_source_inventory(tmp_path)

    assert inventory.paths == (tmp_path / "main.py",)
    assert any("Root type stub __init__.pyi" in item for item in inventory.limitations)


def test_stub_package_prefix_limits_descendant_imports_without_reading_stub(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.pyi").write_bytes(b"\xff")
    (package / "helper.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("import pkg.helper\n", encoding="utf-8")

    inventory = build_source_inventory(tmp_path)

    assert all(path.suffix == ".py" for path in inventory.paths)
    assert ("main.py", "pkg.helper") in inventory.unresolved_imports
    assert any("pkg/__init__.pyi" in item for item in inventory.limitations)
