"""Integration checks for canonical inventories at the mypy boundary."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.source_inventory import build_source_inventory


@pytest.mark.parametrize(
    ("follow_imports", "expected_policy"),
    [(True, "normal"), (False, "skip")],
)
def test_canonical_inventory_policy_builds_and_serializes_pair_provenance(
    tmp_path: Path,
    follow_imports: bool,
    expected_policy: str,
) -> None:
    (tmp_path / "main.py").write_text(
        "from helper import value\n\ndef handler():\n    return value\n",
        encoding="utf-8",
    )
    (tmp_path / "helper.py").write_text("value = 1\n", encoding="utf-8")

    inventory = build_source_inventory(
        tmp_path,
        exclude_patterns=("helper.py",),
        follow_imports=follow_imports,
    )
    assert inventory.follow_imports is follow_imports
    assert inventory.unresolved_imports == (
        ("main.py", "helper"),
        ("main.py", "helper.value"),
    )

    analyzer = MypyAnalyzer(
        tmp_path / "main.py",
        module_root=tmp_path,
        source_inventory=inventory,
    )
    fingerprint, sources = analyzer._cache_fingerprint()

    assert sources == {"main.py": inventory.files[0].sha256}
    assert fingerprint
    assert analyzer._effective_follow_imports() == expected_policy
    analyzer._ensure_mypy_built()
    assert "main" in analyzer._trees
    analyzer.release_typed_snapshot()
