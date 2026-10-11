"""Bulk-analysis exclusion census reuse and cache invalidation."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.source_inventory import build_source_inventory
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo

if TYPE_CHECKING:
    from collections.abc import Iterator


def _analyzer_and_endpoint(tmp_path: Path) -> tuple[MypyAnalyzer, Endpoint]:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "app.py"
    source.write_text("def handler() -> bool:\n    return True\n", encoding="utf-8")
    inventory = build_source_inventory(project, include_patterns=("app.py",))
    analyzer = MypyAnalyzer(project, source_inventory=inventory)
    endpoint = Endpoint(
        path="/value",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="app",
            file_path=source,
            line_number=1,
        ),
    )
    return analyzer, endpoint


def _track_census_walks(monkeypatch: pytest.MonkeyPatch, root: Path) -> list[str]:
    walks: list[str] = []
    original = Path.rglob

    def tracked(path: Path, pattern: str) -> Iterator[Path]:
        if path.resolve() == root.resolve() and pattern == "*":
            walks.append(pattern)
        return original(path, pattern)

    monkeypatch.setattr(Path, "rglob", tracked)
    return walks


def test_bulk_cache_cycle_reuses_census_and_next_cycle_detects_new_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyzer, endpoint = _analyzer_and_endpoint(tmp_path)
    walks = _track_census_walks(monkeypatch, analyzer.source_root)

    analyzer.analyze_endpoints([endpoint], use_cache=True)
    assert analyzer.cache_path.exists()
    assert len(walks) == 2

    analyzer.analyze_endpoints([endpoint], use_cache=True)
    assert len(walks) == 3

    before, _ = analyzer._cache_fingerprint()
    assert len(walks) == 4
    (analyzer.source_root / "blocked.py").write_text(
        "def excluded() -> int:\n    return 1\n", encoding="utf-8"
    )
    after, _ = analyzer._cache_fingerprint()
    assert after != before
    assert len(walks) == 5

    analyzer.analyze_endpoints([endpoint], use_cache=True)
    assert len(walks) == 7


def test_excluded_alias_created_during_build_prevents_cache_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyzer, endpoint = _analyzer_and_endpoint(tmp_path)
    original_build = analyzer._ensure_mypy_built
    walks = _track_census_walks(monkeypatch, analyzer.source_root)
    created = False

    def build_then_add_alias() -> None:
        nonlocal created
        original_build()
        if not created:
            (analyzer.source_root / "blocked.py").write_text(
                "def excluded() -> int:\n    return 1\n", encoding="utf-8"
            )
            created = True

    monkeypatch.setattr(analyzer, "_ensure_mypy_built", build_then_add_alias)
    analyzer.analyze_endpoints([endpoint], use_cache=True)

    assert created
    assert not analyzer.cache_path.exists()
    assert len(walks) == 2


def test_failed_bulk_build_releases_census_for_fresh_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyzer, endpoint = _analyzer_and_endpoint(tmp_path)
    walks = _track_census_walks(monkeypatch, analyzer.source_root)
    before, _ = analyzer._cache_fingerprint()
    assert len(walks) == 1

    def fail_build() -> None:
        raise RuntimeError("injected build failure")

    monkeypatch.setattr(analyzer, "_ensure_mypy_built", fail_build)
    with pytest.raises(RuntimeError, match="injected build failure"):
        analyzer.analyze_endpoints([endpoint], use_cache=False)
    assert len(walks) == 2

    (analyzer.source_root / "blocked.py").write_text(
        "def excluded() -> int:\n    return 1\n", encoding="utf-8"
    )
    after, _ = analyzer._cache_fingerprint()
    assert after != before
    assert len(walks) == 3
