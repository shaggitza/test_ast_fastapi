#!/usr/bin/env python3
"""Run pytest files in isolated processes to bound mypy heap accumulation."""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_MIN_AVAILABLE_MEMORY_MIB = 2_048
_DEFAULT_MIN_FREE_DISK_MIB = 5_120
_DEFAULT_TIMEOUT_SECONDS = 900


def _available_memory_mib() -> int | None:
    """Read Linux available memory without adding a psutil dependency."""
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _free_disk_mib() -> int:
    return shutil.disk_usage(_REPO_ROOT).free // (1024 * 1024)


def _test_files(paths: list[Path]) -> list[Path]:
    discovered: set[Path] = set()
    for supplied in paths:
        path = supplied if supplied.is_absolute() else (_REPO_ROOT / supplied)
        path = path.resolve()
        try:
            path.relative_to(_REPO_ROOT)
        except ValueError as exc:
            raise ValueError(f"test path escapes repository root: {supplied}") from exc
        if path.is_file():
            if path.name.startswith("test_") and path.suffix == ".py":
                discovered.add(path)
            continue
        if path.is_dir():
            discovered.update(item.resolve() for item in path.rglob("test_*.py"))
            continue
        raise ValueError(f"test path does not exist: {supplied}")
    return sorted(discovered, key=lambda item: item.as_posix())


def _clean_local_caches() -> None:
    for relative in (".mypy_cache", ".pytest_cache"):
        shutil.rmtree(_REPO_ROOT / relative, ignore_errors=True)


def _guard_resources(min_memory_mib: int, min_disk_mib: int) -> None:
    memory = _available_memory_mib()
    if memory is not None and memory < min_memory_mib:
        raise RuntimeError(
            f"available memory {memory} MiB is below the {min_memory_mib} MiB safety floor"
        )
    disk = _free_disk_mib()
    if disk < min_disk_mib:
        raise RuntimeError(f"free disk {disk} MiB is below the {min_disk_mib} MiB safety floor")


def _relative(path: Path) -> str:
    try:
        return path.relative_to(_REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate a timed-out pytest process and descendants without touching other jobs."""
    if process.poll() is not None:
        return
    if os.name == "posix":
        os.killpg(process.pid, signal.SIGTERM)
    else:  # pragma: no cover - exercised only on Windows
        process.terminate()
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix":
        os.killpg(process.pid, signal.SIGKILL)
    else:  # pragma: no cover - exercised only on Windows
        process.kill()
    process.wait()


def run(
    files: list[Path],
    *,
    pytest_args: list[str],
    min_memory_mib: int,
    min_disk_mib: int,
    timeout_seconds: int,
) -> int:
    """Run each test file in a fresh process and stop at the first failure."""
    if not files:
        print("No test files discovered", file=sys.stderr)
        return 2
    started = time.monotonic()
    environment = os.environ.copy()
    environment.setdefault("PYTHONHASHSEED", "0")
    with tempfile.TemporaryDirectory(prefix="endpoint-detector-pytest-") as temp_root:
        for index, test_file in enumerate(files, 1):
            _guard_resources(min_memory_mib, min_disk_mib)
            relative = _relative(test_file)
            print(f"[{index:02d}/{len(files):02d}] {relative}", flush=True)
            base_temp = Path(temp_root) / f"batch-{index:03d}"
            command = [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                str(test_file),
                "--basetemp",
                str(base_temp),
                *pytest_args,
            ]
            process = subprocess.Popen(
                command,
                cwd=_REPO_ROOT,
                env=environment,
                start_new_session=True,
            )
            try:
                return_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                _stop_process_group(process)
                print(
                    f"TIMEOUT after {timeout_seconds}s: {relative}",
                    file=sys.stderr,
                )
                return_code = 124
            except BaseException:
                _stop_process_group(process)
                raise
            finally:
                _clean_local_caches()
            if return_code != 0:
                print(f"FAILED: {relative}", file=sys.stderr)
                return return_code
    elapsed = time.monotonic() - started
    print(f"Passed {len(files)} isolated test files in {elapsed:.1f}s")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[Path("tests")],
        help="test files/directories (default: tests)",
    )
    parser.add_argument(
        "--pytest-arg",
        action="append",
        default=[],
        help="additional pytest argument; repeat for multiple arguments",
    )
    parser.add_argument(
        "--min-available-memory-mib",
        type=int,
        default=_DEFAULT_MIN_AVAILABLE_MEMORY_MIB,
    )
    parser.add_argument(
        "--min-free-disk-mib",
        type=int,
        default=_DEFAULT_MIN_FREE_DISK_MIB,
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=_DEFAULT_TIMEOUT_SECONDS,
        help="maximum wall time for each isolated test file (default: 900)",
    )
    arguments = parser.parse_args()
    if arguments.min_available_memory_mib < 0 or arguments.min_free_disk_mib < 0:
        parser.error("resource safety floors must be non-negative")
    if arguments.timeout_seconds < 1:
        parser.error("timeout must be at least one second")
    try:
        files = _test_files(arguments.paths)
        return run(
            files,
            pytest_args=arguments.pytest_arg,
            min_memory_mib=arguments.min_available_memory_mib,
            min_disk_mib=arguments.min_free_disk_mib,
            timeout_seconds=arguments.timeout_seconds,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"Resource-bounded test run aborted: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
