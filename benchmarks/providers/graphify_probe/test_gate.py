"""Tests for the static STOP gate and fixture oracle; never invokes Graphify."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from benchmarks.providers.graphify_probe.gate import (
    ProbeUnavailable,
    assess_gate,
    require_extraction_eligible,
)

ROOT = Path(__file__).parent


class GateTests(unittest.TestCase):
    def test_current_evidence_blocks_extraction(self) -> None:
        status = assess_gate(ROOT / "evidence.json")
        self.assertFalse(status.eligible)
        self.assertGreaterEqual(len(status.reasons), 5)

    def test_require_gate_fails_before_any_launcher_exists(self) -> None:
        with self.assertRaisesRegex(ProbeUnavailable, "no-execution-launcher"):
            require_extraction_eligible(ROOT / "evidence.json")

    def test_fixture_oracle_covers_required_scenarios_and_ranges(self) -> None:
        contract = json.loads((ROOT / "fixtures/expectations.json").read_text())
        self.assertIn("UTF-8 byte offsets differ", " ".join(contract["required_edge_cases"]))
        self.assertEqual(contract["baseline_only_files"], ["deleted.py"])
        expected_bytes = contract["line_expectations"]["target/caller.py"][
            "utf8_prefix_byte_length"
        ]
        self.assertEqual(expected_bytes, 5)
        for side in ("baseline", "target"):
            fixture = ROOT / "fixtures" / side
            self.assertTrue((fixture / "caller.py").is_file())
            self.assertTrue((fixture / "provider.py").is_file())
        self.assertFalse((ROOT / "fixtures/target/deleted.py").exists())

        for side in ("baseline", "target"):
            caller = (ROOT / "fixtures" / side / "caller.py").read_bytes()
            lines = caller.decode("utf-8").splitlines()
            expected = contract["line_expectations"][f"{side}/caller.py"]
            self.assertEqual(len("café".encode()), expected["utf8_prefix_byte_length"])
            self.assertEqual(len("café"), 4)
            for line_number in expected["expected_call_lines"]:
                self.assertIn("(", lines[line_number - 1])
            self.assertTrue(lines[expected["expected_import_line"] - 1].startswith("from "))
            byte_spans = []
            char_spans = []
            for token in ("renamed_target()", "return call()"):
                char_start = caller.decode("utf-8").index(token)
                char_end = char_start + len(token)
                byte_start = len(caller.decode("utf-8")[:char_start].encode("utf-8"))
                byte_end = len(caller.decode("utf-8")[:char_end].encode("utf-8"))
                byte_spans.append([byte_start, byte_end])
                char_spans.append([char_start, char_end])
            self.assertEqual(byte_spans, expected["expected_utf8_file_byte_spans"])
            self.assertEqual(char_spans, expected["expected_utf8_character_spans"])

    def test_evidence_records_mismatched_raw_and_adapter_contracts(self) -> None:
        evidence = json.loads((ROOT / "evidence.json").read_text())
        interface = evidence["package_interface"]
        self.assertIn("not adapter", interface["no_cluster_output_contract"])
        self.assertFalse(interface["extract_command_parses_directed_option"])
        self.assertFalse(evidence["runtime_observation"]["extraction_executed"])


if __name__ == "__main__":
    unittest.main()
