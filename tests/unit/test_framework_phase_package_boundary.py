"""The product comparator must work without the checkout's benchmark namespace."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer import framework_phase_comparison


def test_phase_comparator_imports_from_product_only_archive(tmp_path: Path) -> None:
    package = Path(framework_phase_comparison.__file__).resolve().parents[1]
    archive = tmp_path / "installed_product.zip"
    with zipfile.ZipFile(archive, "w") as output:
        for source in package.rglob("*.py"):
            output.write(source, source.relative_to(package.parent))
    probe = r"""
import importlib.abc
import sys
from pathlib import Path

class RejectBenchmarks(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "benchmarks" or fullname.startswith("benchmarks."):
            raise AssertionError("installed product imported benchmarks")
        return None

sys.meta_path.insert(0, RejectBenchmarks())
sys.path.insert(0, sys.argv[1])
from fastapi_endpoint_detector.analyzer.framework_phase_comparison import compare_phase_artifacts
from fastapi_endpoint_detector.analyzer.runtime_artifact_comparison import ComparisonError, compare

assert sys.argv[1] in sys.modules[compare.__module__].__file__
missing = compare_phase_artifacts(Path("missing-secure.json"), Path("missing-runtime.json"))
assert missing.status == "unavailable" and "receipt validation failed" in missing.reason
for raw in ('{"schema_version":1,"schema_version":1}', '{"schema_version":NaN}'):
    path = Path("invalid.json")
    path.write_text(raw, encoding="utf-8")
    try:
        compare(path, path)
    except ComparisonError as error:
        assert "invalid JSON" in str(error)
    else:
        raise AssertionError("invalid artifact accepted")
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(archive)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("script_name", "supports_help"),
    [
        ("compare_runtime.py", True),
        ("evaluate.py", True),
        ("build_training_dataset.py", True),
        ("verify_truth_release_v2.py", True),
        ("produce_runtime.py", False),
    ],
)
def test_direct_benchmark_startup_bootstraps_checkout_source_tree(
    tmp_path: Path, script_name: str, supports_help: bool
) -> None:
    repository = Path(__file__).resolve().parents[2]
    script = repository / "benchmarks/real_world" / script_name
    probe = r"""
import runpy
import sys
from pathlib import Path

repository, script = map(Path, sys.argv[1:3])
source = (repository / "src").resolve()
checkout = repository.resolve()
sys.meta_path[:] = [
    finder for finder in sys.meta_path
    if "editable" not in type(finder).__name__.lower()
]
sys.path[:] = [
    entry for entry in sys.path
    if not entry
    or (Path(entry).resolve() != source and source not in Path(entry).resolve().parents
        and Path(entry).resolve() != checkout and checkout not in Path(entry).resolve().parents)
]
if sys.argv[3] == "help":
    sys.argv = [str(script), "--help"]
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as error:
        assert error.code == 0, error.code
    else:
        raise AssertionError("--help did not exit")
else:
    sys.argv = [str(script)]
    runpy.run_path(str(script), run_name="__main__")

from fastapi_endpoint_detector.analyzer import runtime_artifact_comparison

loaded_from = Path(runtime_artifact_comparison.__file__).resolve()
assert loaded_from.is_relative_to(source), loaded_from
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            probe,
            str(repository),
            str(script),
            "help" if supports_help else "import",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
