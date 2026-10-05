from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest
from benchmarks.incremental_mypy_dag import (
    _equivalence_check,
    make_dag,
    retarget_import_source,
)

from fastapi_endpoint_detector.analyzer import mypy_incremental
from fastapi_endpoint_detector.analyzer.mypy_incremental import (
    BuildConfig,
    IncrementalBuildError,
    MypyIncrementalProvider,
    TypedBuild,
)

if TYPE_CHECKING:
    from pathlib import Path


def _source_inventory(root: Path) -> dict[str, Path]:
    return {path.stem: path for path in root.glob("*.py")}


def _dag(root: Path, size: int = 6) -> dict[str, Path]:
    for index in range(size):
        next_import = f"from m{index + 1} import f{index + 1}\n" if index + 1 < size else ""
        next_call = (
            f"    return f{index + 1}(value)\n" if index + 1 < size else "    return value\n"
        )
        (root / f"m{index}.py").write_text(
            f"{next_import}\ndef f{index}(value: int) -> int:\n{next_call}", encoding="utf-8"
        )
    return _source_inventory(root)


def _fresh(root: Path, inventory: dict[str, Path]) -> TypedBuild:
    return MypyIncrementalProvider(BuildConfig(root)).build(inventory)


def test_no_change_reuses_exact_typed_build(tmp_path: Path) -> None:
    inventory = _dag(tmp_path)
    provider = MypyIncrementalProvider(BuildConfig(tmp_path))
    cold = provider.build(inventory)
    warm = provider.build(inventory)
    assert cold.report.mode == "cold_build"
    assert warm.report.mode == "no_change_reuse"
    assert warm.manager is cold.manager
    assert warm.typed_snapshot() == cold.typed_snapshot()


def test_unsupported_engine_is_rejected_before_cold_build(tmp_path: Path) -> None:
    with pytest.raises(IncrementalBuildError, match="unsupported typed build engine"):
        MypyIncrementalProvider(BuildConfig(tmp_path, engine="unsupported-engine"))


@pytest.mark.parametrize("reported_version", ["1.20.0", "2.3.9", "2.5.0"])
def test_unvalidated_mypy_version_is_rejected_before_cold_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reported_version: str
) -> None:
    monkeypatch.setattr(mypy_incremental, "version", lambda _package: reported_version)
    with pytest.raises(IncrementalBuildError, match="not validated for fine-grained updates"):
        MypyIncrementalProvider(BuildConfig(tmp_path))


def test_independently_validated_mypy_24_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mypy_incremental, "version", lambda _package: "2.4.0")
    provider = MypyIncrementalProvider(BuildConfig(tmp_path))
    assert provider._mypy_version == "2.4.0"


def test_same_interface_edit_is_real_typed_incremental_update(tmp_path: Path) -> None:
    inventory = _dag(tmp_path)
    provider = MypyIncrementalProvider(BuildConfig(tmp_path))
    cold = provider.build(inventory)
    (tmp_path / "m4.py").write_text(
        "from m5 import f5\n"
        "def f4(value: int) -> int:\n"
        "    adjusted = value + 7\n"
        "    return f5(adjusted)\n",
        encoding="utf-8",
    )
    updated = provider.build(inventory)
    fresh = _fresh(tmp_path, inventory)
    assert updated.report.mode == "incremental_update"
    assert updated.report.updated_modules == ("m4",)
    assert updated.manager is not fresh.manager
    assert updated.typed_snapshot() == fresh.typed_snapshot()
    assert updated.type_maps
    assert updated.report.source_digests_before == cold.report.source_digests_after
    assert updated.report.source_digests_after != updated.report.source_digests_before


def test_signature_change_invalidates_dependents_and_matches_fresh_snapshot(tmp_path: Path) -> None:
    inventory = _dag(tmp_path)
    provider = MypyIncrementalProvider(BuildConfig(tmp_path))
    provider.build(inventory)
    (tmp_path / "m4.py").write_text(
        "from m5 import f5\ndef f4(value: str) -> str:\n    return f5(value)\n",
        encoding="utf-8",
    )
    updated = provider.build(inventory)
    fresh = _fresh(tmp_path, inventory)
    assert updated.report.mode == "incremental_update"
    assert any(target.startswith("m3.") for target in updated.manager.processed_targets)
    assert updated.typed_snapshot() == fresh.typed_snapshot()


def test_import_retarget_and_module_deletion_fall_back_cleanly(tmp_path: Path) -> None:
    inventory = _dag(tmp_path)
    (tmp_path / "alternate.py").write_text(
        "def alternate(value: int) -> int:\n    return value\n", encoding="utf-8"
    )
    inventory["alternate"] = tmp_path / "alternate.py"
    provider = MypyIncrementalProvider(BuildConfig(tmp_path))
    provider.build(inventory)
    (tmp_path / "m0.py").write_text(
        "from alternate import alternate\n"
        "def f0(value: int) -> int:\n"
        "    return alternate(value)\n",
        encoding="utf-8",
    )
    retargeted = provider.build(inventory)
    assert retargeted.report.mode == "fallback_full_rebuild"
    assert "import topology" in (retargeted.report.reason or "")
    assert retargeted.typed_snapshot() == _fresh(tmp_path, inventory).typed_snapshot()

    del inventory["m5"]
    (tmp_path / "m5.py").unlink()
    deleted = provider.build(inventory)
    assert deleted.report.mode == "fallback_full_rebuild"
    assert "inventory identities" in (deleted.report.reason or "")
    assert deleted.typed_snapshot() == _fresh(tmp_path, inventory).typed_snapshot()


def test_cold_build_rejects_followed_local_modules_missing_from_inventory(
    tmp_path: Path,
) -> None:
    (tmp_path / "m0.py").write_text(
        "from m1 import f1\ndef f0(value: int) -> int:\n    return f1(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "m1.py").write_text(
        "def f1(value: int) -> int:\n    return value\n", encoding="utf-8"
    )
    provider = MypyIncrementalProvider(BuildConfig(tmp_path))

    with pytest.raises(IncrementalBuildError, match="omits followed local module 'm1'"):
        provider.build({"m0": tmp_path / "m0.py"})


@pytest.mark.parametrize(
    "python_target", ["3.10", f"{sys.version_info.major}.{sys.version_info.minor}"]
)
def test_benchmark_cold_comparison_uses_the_retained_python_target(
    tmp_path: Path, python_target: str
) -> None:
    inventory = make_dag(tmp_path, 4)
    config = BuildConfig(tmp_path, python_version=python_target)
    retained = MypyIncrementalProvider(config).build(inventory)

    equivalence = _equivalence_check(config, inventory, retained)

    assert equivalence["equivalent_to_independent_cold_build"] is True
    assert equivalence["cache_fingerprint_matches_independent_cold_build"] is True
    assert equivalence["python_version"] == python_target


@pytest.mark.parametrize("module_count", [4, 6])
def test_generated_benchmark_retarget_is_real_and_matches_cold_build(
    tmp_path: Path, module_count: int
) -> None:
    inventory = make_dag(tmp_path, module_count)
    changed_index = module_count // 2
    changed_path = inventory[f"m{changed_index}"]
    original_source = changed_path.read_text(encoding="utf-8")
    old_target = changed_index + 1
    provider = MypyIncrementalProvider(BuildConfig(tmp_path))
    provider.build(inventory)

    retargeted_source = retarget_import_source(original_source, changed_index, module_count)
    new_target = (changed_index + 2) % module_count
    assert old_target != new_target
    assert f"from m{old_target} import f{old_target}" in original_source
    assert f"from m{new_target} import f{new_target}" in retargeted_source
    assert retargeted_source != original_source
    changed_path.write_text(retargeted_source, encoding="utf-8")

    rebuilt = provider.build(inventory)
    fresh = _fresh(tmp_path, inventory)
    assert rebuilt.report.mode == "fallback_full_rebuild"
    assert "import topology" in (rebuilt.report.reason or "")
    assert rebuilt.typed_snapshot() == fresh.typed_snapshot()


def test_unrelated_module_edit_does_not_disturb_unchanged_typed_modules(tmp_path: Path) -> None:
    inventory = _dag(tmp_path)
    provider = MypyIncrementalProvider(BuildConfig(tmp_path))
    before = provider.build(inventory).typed_snapshot()
    (tmp_path / "m5.py").write_text(
        "def f5(value: int) -> int:\n    return value + 19\n", encoding="utf-8"
    )
    after = provider.build(inventory)
    fresh = _fresh(tmp_path, inventory)
    assert after.report.mode == "incremental_update"
    assert after.typed_snapshot() == fresh.typed_snapshot()
    assert after.typed_snapshot()["m0"] == before["m0"]


def test_config_content_change_invalidates_provider_state(tmp_path: Path) -> None:
    inventory = _dag(tmp_path)
    config = tmp_path / "mypy.ini"
    config.write_text(
        "[mypy]\npython_version = 3.11\nignore_missing_imports = False\n",
        encoding="utf-8",
    )
    provider = MypyIncrementalProvider(BuildConfig(tmp_path, config_file=config))
    cold = provider.build(inventory)
    config.write_text(
        "[mypy]\npython_version = 3.11\nignore_missing_imports = True\n",
        encoding="utf-8",
    )
    rebuilt = provider.build(inventory)
    fresh = MypyIncrementalProvider(BuildConfig(tmp_path, config_file=config)).build(inventory)
    assert rebuilt.report.mode == "fallback_full_rebuild"
    assert "configuration/cache fingerprint" in (rebuilt.report.reason or "")
    assert rebuilt.report.cache_fingerprint != cold.report.cache_fingerprint
    assert rebuilt.report.cache_fingerprint == fresh.report.cache_fingerprint
    assert rebuilt.typed_snapshot() == fresh.typed_snapshot()
    assert rebuilt.report.source_digests_before == cold.report.source_digests_after
    assert rebuilt.report.source_digests_after == cold.report.source_digests_after

    unchanged = provider.build(inventory)
    assert unchanged.report.mode == "no_change_reuse"
    assert unchanged.report.reason is None
    assert unchanged.report.cache_fingerprint == fresh.report.cache_fingerprint
    assert unchanged.typed_snapshot() == fresh.typed_snapshot()
    assert unchanged.report.source_digests_before == rebuilt.report.source_digests_after
    assert unchanged.report.source_digests_after == rebuilt.report.source_digests_after
