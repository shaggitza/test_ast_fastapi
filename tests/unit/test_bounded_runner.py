"""Safety and isolation tests for the resource-bounded pytest runner."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
from scripts import run_tests_bounded

if TYPE_CHECKING:
    from pathlib import Path


def test_discovery_rejects_paths_outside_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "test_external.py"
    external.write_text("def test_external(): pass\n", encoding="utf-8")
    monkeypatch.setattr(run_tests_bounded, "_REPO_ROOT", repository)

    with pytest.raises(ValueError, match="escapes repository root"):
        run_tests_bounded._test_files([external])


def test_timeout_stops_isolated_test_and_cleans_local_caches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "test_sleep.py"
    test_file.write_text(
        "import time\n\ndef test_sleep():\n    time.sleep(30)\n",
        encoding="utf-8",
    )
    (tmp_path / ".mypy_cache").mkdir()
    (tmp_path / ".pytest_cache").mkdir()
    monkeypatch.setattr(run_tests_bounded, "_REPO_ROOT", tmp_path)
    started = time.monotonic()

    result = run_tests_bounded.run(
        [test_file],
        pytest_args=[],
        min_memory_mib=0,
        min_disk_mib=0,
        timeout_seconds=1,
    )

    assert result == 124
    assert time.monotonic() - started < 10
    assert not (tmp_path / ".mypy_cache").exists()
    assert not (tmp_path / ".pytest_cache").exists()
