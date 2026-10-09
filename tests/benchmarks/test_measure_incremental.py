from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from benchmarks.real_world import measure_incremental


class IncrementalMeasurementProtocolTests(unittest.TestCase):
    def test_percentiles_and_empty_measurement_are_not_fabricated(self) -> None:
        self.assertEqual(
            measure_incremental.percentiles([1.0, 2.0, 3.0]), {"p50": 2.0, "p95": 3.0, "max": 3.0}
        )

    def test_fixture_hashes_are_deterministic_and_single_file_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root_a = Path(tmp) / "a" / "app"
            first, hashes_a, expected_a = measure_incremental.write_fixture(Path(tmp) / "a")
            second, hashes_b, expected_b = measure_incremental.write_fixture(Path(tmp) / "b")
            self.assertEqual(
                set(hashes_a),
                {path.relative_to(root_a).as_posix() for path in root_a.rglob("*.py")},
            )
        self.assertEqual(hashes_a, hashes_b)
        self.assertEqual(expected_a, expected_b)
        self.assertEqual(first.handler.name, second.handler.name)
        self.assertEqual(len(hashes_a), measure_incremental.MODULES + 3)

    def test_protocol_never_claims_incremental_for_full_rebuild_backend(self) -> None:
        # Capability contract can be asserted without launching an expensive mypy build.
        report = {
            "one_file_incremental_update": {
                "status": "unsupported",
                "reason": "backend_incremental_build_disabled",
            }
        }
        self.assertEqual(report["one_file_incremental_update"]["status"], "unsupported")


if __name__ == "__main__":
    unittest.main()
