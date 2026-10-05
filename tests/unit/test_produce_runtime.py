"""Producer telemetry reports only measured cgroup values."""

from pathlib import Path
from unittest.mock import patch

from fastapi_endpoint_detector.parser.produce_runtime import _peak_memory_bytes


def test_container_peak_reads_kernel_cgroup_counter(tmp_path: Path) -> None:
    counter = tmp_path / "memory.peak"
    counter.write_text("8192\n", encoding="ascii")
    with patch("fastapi_endpoint_detector.parser.produce_runtime.Path", return_value=counter):
        assert _peak_memory_bytes() == 8192


def test_container_peak_is_unsupported_when_kernel_counter_is_unavailable(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"
    with patch("fastapi_endpoint_detector.parser.produce_runtime.Path", return_value=missing):
        assert _peak_memory_bytes() is None
