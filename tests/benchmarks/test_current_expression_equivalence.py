"""Cold-equivalence gate controls using only in-memory retained/cold stand-ins."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from benchmarks import incremental_mypy_dag as benchmark
from fastapi_endpoint_detector.analyzer.live_expression_types import ModuleExpressionTypes
from fastapi_endpoint_detector.analyzer.mypy_incremental import BuildConfig

if TYPE_CHECKING:
    from pytest import MonkeyPatch


class _State:
    def __init__(self, digest: str = "a" * 64) -> None:
        self.report = SimpleNamespace(cache_fingerprint="same-config-and-source")
        self._live = (ModuleExpressionTypes("fixture", True, 2, 1, 0, digest),)

    def typed_snapshot(self) -> dict[str, tuple[str, ...]]:
        return {"fixture": ("unchanged-legacy-evidence",)}

    def live_expression_type_snapshot(self) -> tuple[ModuleExpressionTypes, ...]:
        return self._live


def test_new_gate_flag_is_required_and_literal_true() -> None:
    old = {
        "equivalent_to_independent_cold_build": True,
        "cache_fingerprint_matches_independent_cold_build": True,
    }
    assert not benchmark._equivalence_passed({"cold_equivalence": old})
    for value in (False, None, 1, "true"):
        evidence = {**old, "live_expression_types_match_independent_cold_build": value}
        assert not benchmark._equivalence_passed({"cold_equivalence": evidence})
    evidence = {**old, "live_expression_types_match_independent_cold_build": True}
    assert benchmark._equivalence_passed({"cold_equivalence": evidence})


def test_live_type_mismatch_blocks_success_after_legacy_equality(
    monkeypatch: MonkeyPatch,
) -> None:
    fresh = _State("b" * 64)

    class FreshProvider:
        def __init__(self, _config: object) -> None:
            pass

        def build(self, _inventory: object) -> _State:
            return fresh

    monkeypatch.setattr(benchmark, "MypyIncrementalProvider", FreshProvider)
    with pytest.raises(RuntimeError, match="current expression types differ"):
        benchmark._equivalence_check(BuildConfig(Path("/in-memory-only")), {}, _State())


def test_live_type_match_reports_projection_counts(monkeypatch: MonkeyPatch) -> None:
    fresh = _State()

    class FreshProvider:
        def __init__(self, _config: object) -> None:
            pass

        def build(self, _inventory: object) -> _State:
            return fresh

    monkeypatch.setattr(benchmark, "MypyIncrementalProvider", FreshProvider)
    result = benchmark._equivalence_check(BuildConfig(Path("/in-memory-only")), {}, _State())
    assert result["live_expression_types_match_independent_cold_build"] is True
    assert result["live_expression_type_count"] == 2
    assert result["live_expression_mapped_type_count"] == 1
    assert result["live_expression_owned_typevar_count"] == 0
    assert result["live_expression_module_digests"] == {"fixture": "a" * 64}


def test_raw_retained_map_counter_is_preserved() -> None:
    manager = SimpleNamespace(
        all_types={object(): object(), object(): object()},
        ast_cache={},
        fscache=SimpleNamespace(read_cache={}, hash_cache={}),
    )
    state = SimpleNamespace(manager=SimpleNamespace(manager=manager), modules={})
    assert benchmark._cache_stats(state)["typed_expression_count"] == len(manager.all_types) == 2
