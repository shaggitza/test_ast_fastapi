from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from fastapi_endpoint_detector.models.effect_contract_audit import EffectContractAudit

MODULE_PATH = Path(__file__).parents[2] / "scripts" / "validate_gh97_inventory.py"
SOURCE_BYTES = b"abcdefgh"
SOURCE_HASH = hashlib.sha256(SOURCE_BYTES).hexdigest()
SPEC = importlib.util.spec_from_file_location("gh97_validator", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def row(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "case_id": "case-a",
        "packet_sha256": "a" * 64,
        "path": "app.py",
        "source_sha256": SOURCE_HASH,
        "start_byte": 1,
        "end_byte": 4,
        "file_bytes": 8,
        "call_ast_sha256": "b" * 64,
        "callee_syntax": "client.get",
        "outcome": "supported_match",
        "applicability": {"distribution": "redis", "version": "5.2.1"},
        "preset": {
            "id": "redis-v1",
            "version": "1.0.0",
            "revision": "1",
            "config_sha256": "c" * 64,
            "contract_id": "redis",
        },
        "cli_observation": {
            "status": "observed",
            "invocation_id": "run-1",
            "output_sha256": "d" * 64,
            "row_key": "result-1",
        },
    }
    value.update(updates)
    return value


def mapped_case() -> tuple[dict[str, object], bytes, dict[str, object]]:
    value = row()
    output_row = {
        "id": "result-1",
        "path": "app.py",
        "source_sha256": SOURCE_HASH,
        "start": 1,
        "end": 4,
        "call_ast_sha256": "b" * 64,
        "callee": "client.get",
    }
    output = json.dumps({"results": [output_row]}, separators=(",", ":")).encode()
    digest = hashlib.sha256(output).hexdigest()
    key = [
        value[k]
        for k in ("case_id", "packet_sha256", "path", "start_byte", "end_byte", "call_ast_sha256")
    ]
    mapping: dict[str, object] = {
        "schema_version": 1,
        "invocations": [
            {
                "invocation_id": "run-1",
                "output_sha256": digest,
                "rows": [
                    {
                        "inventory_key": key,
                        "rows_pointer": "/results",
                        "output_pointer": "/results/0",
                        "row_sha256": hashlib.sha256(
                            json.dumps(
                                output_row,
                                sort_keys=True,
                                separators=(",", ":"),
                                ensure_ascii=False,
                            ).encode()
                        ).hexdigest(),
                        "fields": {
                            "row_key": "/id",
                            "path": "/path",
                            "source_sha256": "/source_sha256",
                            "start_byte": "/start",
                            "end_byte": "/end",
                            "call_ast_sha256": "/call_ast_sha256",
                            "callee_syntax": "/callee",
                        },
                    }
                ],
                "unobserved_rows": [],
            }
        ],
    }
    value["cli_observation"]["output_sha256"] = digest  # type: ignore[index]
    return value, output, mapping


def unobserved_case() -> tuple[dict[str, object], bytes, dict[str, object]]:
    value = row(
        outcome="unobserved_by_cli",
        reason="not_emitted_by_endpoint_reachable_cli",
        cli_observation={
            "status": "unobserved_by_cli",
            "invocation_id": "run-2",
            "output_sha256": None,
            "row_key": None,
        },
    )
    output = json.dumps({"results": []}, separators=(",", ":")).encode()
    digest = hashlib.sha256(output).hexdigest()
    value["cli_observation"]["output_sha256"] = digest  # type: ignore[index]
    key = [
        value[k]
        for k in ("case_id", "packet_sha256", "path", "start_byte", "end_byte", "call_ast_sha256")
    ]
    fields = {
        "path": "/path",
        "source_sha256": "/source_sha256",
        "start_byte": "/start_byte",
        "end_byte": "/end_byte",
        "call_ast_sha256": "/call_ast_sha256",
        "callee_syntax": "/callee_syntax",
    }
    mapping: dict[str, object] = {
        "schema_version": 1,
        "invocations": [
            {
                "invocation_id": "run-2",
                "output_sha256": digest,
                "rows": [],
                "unobserved_rows": [
                    {"inventory_key": key, "rows_pointer": "/results", "fields": fields}
                ],
            }
        ],
    }
    return value, output, mapping


class InventoryValidatorTests(unittest.TestCase):
    def test_public_cli_projection_fails_closed_for_exact_row_claim(self) -> None:
        value, output, mapping = mapped_case()
        errors = VALIDATOR.validate_rows(
            [value], {hashlib.sha256(output).hexdigest(): output}, mapping
        )
        self.assertTrue(any("exact observed status is unsupported" in error for error in errors))
        report_path = Path(__file__).parents[1] / "fixtures" / "gh97_audit_effect_contracts_v1.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(VALIDATOR._validate_public_audit_v1(report), [])
        audit = EffectContractAudit.model_validate(report)
        self.assertEqual(audit.model_dump(mode="json", exclude_none=True), report)
        report["metadata"] = {"ignored": []}
        self.assertTrue(VALIDATOR._validate_public_audit_v1(report))
        del report["metadata"]
        report["occurrences"][0]["endpoints"][0] = {}
        self.assertTrue(VALIDATOR._validate_public_audit_v1(report))
        report["schema_version"] = 2
        self.assertTrue(VALIDATOR._validate_public_audit_v1(report))

    def test_model_rejects_impossible_complete_inventory_and_summary(self) -> None:
        report_path = Path(__file__).parents[1] / "fixtures" / "gh97_audit_effect_contracts_v1.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["scope"]["inventory_status"] = "unavailable"
        self.assertTrue(VALIDATOR._validate_public_audit_v1(report))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["summary"]["matched_calls"] += 1
        self.assertTrue(VALIDATOR._validate_public_audit_v1(report))

    def test_public_audit_requires_exact_json_types_from_model_dump(self) -> None:
        report_path = Path(__file__).parents[1] / "fixtures" / "gh97_audit_effect_contracts_v1.json"
        mutations: tuple[tuple[tuple[str | int, ...], object], ...] = (
            (("summary", "physical_occurrences"), True),
            (("summary", "physical_occurrences"), 1.0),
            (("occurrences", 0, "line"), True),
            (("occurrences", 0, "endpoints", 0, "handler_line"), True),
        )
        for path, replacement in mutations:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            target: Any = report
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            self.assertTrue(
                VALIDATOR._validate_public_audit_v1(report),
                f"accepted type mutation at {path!r}",
            )

    def test_public_audit_rejects_non_finite_json_numbers(self) -> None:
        report_path = Path(__file__).parents[1] / "fixtures" / "gh97_audit_effect_contracts_v1.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["occurrences"][0]["column"] = float("nan")
        self.assertTrue(VALIDATOR._validate_public_audit_v1(report))

    def test_authenticated_actual_report_is_accepted_only_as_unsupported(self) -> None:
        value = row(
            outcome="unsupported",
            reason="other_frozen_reason",
            cli_observation={
                "status": "unsupported",
                "invocation_id": "run-public-v1",
                "output_sha256": None,
                "row_key": None,
            },
        )
        report_path = Path(__file__).parents[1] / "fixtures" / "gh97_audit_effect_contracts_v1.json"
        output = report_path.read_bytes()
        digest = hashlib.sha256(output).hexdigest()
        value["cli_observation"]["output_sha256"] = digest  # type: ignore[index]
        self.assertEqual(VALIDATOR.validate_rows([value], {digest: output}, mapping=None), [])
        forged = json.loads(output)
        forged["metadata"] = {"ignored": []}
        forged_bytes = json.dumps(forged).encode()
        forged_digest = hashlib.sha256(forged_bytes).hexdigest()
        value["cli_observation"]["output_sha256"] = forged_digest  # type: ignore[index]
        self.assertTrue(
            VALIDATOR.validate_rows([value], {forged_digest: forged_bytes}, mapping=None)
        )

    def test_rejects_reversed_span_and_overshoot(self) -> None:
        reversed_errors = VALIDATOR.validate_rows([row(start_byte=4, end_byte=1)])
        overshoot_errors = VALIDATOR.validate_rows([row(end_byte=9)])
        self.assertTrue(any("start_byte" in error for error in reversed_errors))
        self.assertTrue(any("start_byte" in error for error in overshoot_errors))

    def test_rejects_duplicate_call_keys_within_case(self) -> None:
        errors = VALIDATOR.validate_rows([row(), row()])
        self.assertTrue(any("duplicate call key" in error for error in errors))

    def test_rejects_supported_row_with_null_bindings_or_missing_cli_identity(self) -> None:
        null_identity = row(
            applicability={"distribution": None, "version": None},
            preset={
                "id": None,
                "version": None,
                "revision": None,
                "config_sha256": None,
                "contract_id": None,
            },
        )
        errors = VALIDATOR.validate_rows([null_identity])
        self.assertTrue(any("supported outcome" in error for error in errors))
        missing_observation = row(
            cli_observation={
                "status": "observed",
                "invocation_id": None,
                "output_sha256": None,
                "row_key": None,
            }
        )
        errors = VALIDATOR.validate_rows([missing_observation])
        self.assertTrue(any("observed CLI row" in error for error in errors))

    def test_supported_outcomes_require_observed_status_and_unknown_states_fail(self) -> None:
        for status in ("not_run", "unobserved_by_cli", "unavailable", "mystery"):
            errors = VALIDATOR.validate_rows(
                [
                    row(
                        cli_observation={
                            "status": status,
                            "invocation_id": None,
                            "output_sha256": None,
                            "row_key": None,
                        }
                    )
                ]
            )
            self.assertTrue(
                any(
                    "supported outcomes require an observed" in error
                    or "unknown CLI status" in error
                    for error in errors
                ),
                status,
            )

    def test_rejects_reversed_out_of_file_and_out_of_call_subspans(self) -> None:
        binding = {
            "kind": "keyword",
            "name": "key",
            "span_start": 3,
            "span_end": 2,
            "source_path": "app.py",
            "source_sha256": SOURCE_HASH,
            "source_file_bytes": 8,
            "expression_sha256": "f" * 64,
            "dynamic": False,
        }
        reversed_errors = VALIDATOR.validate_rows([row(bindings=[binding])])
        binding["span_start"], binding["span_end"] = 8, 9
        overshoot_errors = VALIDATOR.validate_rows([row(bindings=[binding])])
        binding["span_start"], binding["span_end"] = 0, 1
        out_of_call_errors = VALIDATOR.validate_rows([row(bindings=[binding])])
        self.assertTrue(any("invalid source span" in error for error in reversed_errors))
        self.assertTrue(any("invalid source span" in error for error in overshoot_errors))
        self.assertTrue(any("within its call source span" in error for error in out_of_call_errors))
        binding["span_start"], binding["span_end"] = 2, 3
        binding["source_path"] = "other.py"
        wrong_file_errors = VALIDATOR.validate_rows([row(bindings=[binding])])
        self.assertTrue(
            any(
                "binding evidence must be within its call source span" in error
                for error in wrong_file_errors
            )
        )

    def test_external_resource_definition_requires_explicit_file_and_hash(self) -> None:
        resource = {
            "name": "Bucket",
            "span_start": 1,
            "span_end": 4,
            "source_path": "settings.py",
            "source_sha256": hashlib.sha256(b"0123456789").hexdigest(),
            "source_file_bytes": 10,
            "expression_sha256": "f" * 64,
            "state": "present",
        }
        unresolved = row(
            outcome="incomplete",
            reason="dynamic_or_missing_evidence",
            cli_observation={
                "status": "not_run",
                "invocation_id": None,
                "output_sha256": None,
                "row_key": None,
            },
            resource_components=[resource],
        )
        self.assertEqual(VALIDATOR.validate_rows([unresolved]), [])
        resource["source_sha256"] = None
        errors = VALIDATOR.validate_rows([unresolved])
        self.assertTrue(any("source path and source SHA-256" in error for error in errors))

    def test_frozen_source_bytes_authenticate_declared_length_and_hash(self) -> None:
        unresolved = row(
            outcome="incomplete",
            reason="dynamic_or_missing_evidence",
            cli_observation={
                "status": "not_run",
                "invocation_id": None,
                "output_sha256": None,
                "row_key": None,
            },
        )
        valid_sources = {("case-a", "app.py"): SOURCE_BYTES}
        self.assertEqual(
            VALIDATOR.validate_rows([unresolved], source_bytes_by_identity=valid_sources), []
        )
        errors = VALIDATOR.validate_rows(
            [unresolved], source_bytes_by_identity={("case-a", "app.py"): b"tampered"}
        )
        self.assertTrue(any("source byte identity mismatch" in error for error in errors))

    def test_mapping_rejects_duplicate_missing_and_tampered_output(self) -> None:
        value, output, mapping = mapped_case()
        digest = hashlib.sha256(output).hexdigest()
        invocations = cast("list[dict[str, Any]]", mapping["invocations"])
        invocations[0]["rows"].append(dict(invocations[0]["rows"][0]))
        errors = VALIDATOR.validate_rows([value], {digest: output}, mapping)
        self.assertTrue(any("duplicate inventory mapping" in error for error in errors))
        value, output, mapping = mapped_case()
        cast("list[dict[str, Any]]", mapping["invocations"])[0]["rows"] = []
        self.assertTrue(
            any(
                "prove each observed row" in error
                for error in VALIDATOR.validate_rows(
                    [value], {hashlib.sha256(output).hexdigest(): output}, mapping
                )
            )
        )
        value, output, mapping = mapped_case()
        forged_output = output.replace(b'"path":"app.py"', b'"path":"evil.py"')
        forged_hash = hashlib.sha256(forged_output).hexdigest()
        invocations = cast("list[dict[str, Any]]", mapping["invocations"])
        invocations[0]["output_sha256"] = forged_hash
        value["cli_observation"]["output_sha256"] = forged_hash  # type: ignore[index]
        row_item = invocations[0]["rows"][0]
        forged_row = json.loads(forged_output)["results"][0]
        row_item["row_sha256"] = hashlib.sha256(
            json.dumps(
                forged_row, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        ).hexdigest()
        errors = VALIDATOR.validate_rows([value], {forged_hash: forged_output}, mapping)
        self.assertTrue(any("physical field mismatch: path" in error for error in errors))
        value, output, mapping = mapped_case()
        tampered = output + b" "
        self.assertTrue(
            any(
                "hash mismatch" in error
                for error in VALIDATOR.validate_rows(
                    [value], {hashlib.sha256(output).hexdigest(): tampered}, mapping
                )
            )
        )

    def test_rejects_unobserved_claim_but_accepts_unresolved_not_run(self) -> None:
        unobserved, output, mapping = unobserved_case()
        unresolved = row(
            start_byte=5,
            end_byte=7,
            outcome="incomplete",
            reason="dynamic_or_missing_evidence",
            applicability={"distribution": None, "version": None},
            preset={
                "id": None,
                "version": None,
                "revision": None,
                "config_sha256": None,
                "contract_id": None,
            },
            cli_observation={
                "status": "not_run",
                "invocation_id": None,
                "output_sha256": None,
                "row_key": None,
            },
        )
        errors = VALIDATOR.validate_rows(
            [unobserved, unresolved], {hashlib.sha256(output).hexdigest(): output}, mapping
        )
        self.assertTrue(any("absence cannot be proven" in error for error in errors))

    def test_unobserved_requires_authenticated_absence_from_parsed_output(self) -> None:
        unobserved, _output, mapping = unobserved_case()
        row_item = {
            "path": "app.py",
            "source_sha256": SOURCE_HASH,
            "start_byte": 1,
            "end_byte": 4,
            "call_ast_sha256": "b" * 64,
            "callee_syntax": "client.get",
        }
        present_output = json.dumps({"results": [row_item]}, separators=(",", ":")).encode()
        digest = hashlib.sha256(present_output).hexdigest()
        unobserved["cli_observation"]["output_sha256"] = digest  # type: ignore[index]
        invocation = cast("list[dict[str, Any]]", mapping["invocations"])[0]
        invocation["output_sha256"] = digest
        errors = VALIDATOR.validate_rows([unobserved], {digest: present_output}, mapping)
        self.assertTrue(any("absence cannot be proven" in error for error in errors))

    def test_authenticated_json_rejects_duplicate_members_at_nested_ingresses(self) -> None:
        report_path = Path(__file__).parents[1] / "fixtures" / "gh97_audit_effect_contracts_v1.json"
        report_bytes = report_path.read_bytes()
        duplicate_report = report_bytes.replace(
            b'"handler_line": 5', b'"handler_line": 5, "handler_line": 5', 1
        )
        self.assertNotEqual(duplicate_report, report_bytes)
        digest = hashlib.sha256(duplicate_report).hexdigest()
        value = row(
            outcome="unsupported",
            reason="other_frozen_reason",
            cli_observation={
                "status": "unsupported",
                "invocation_id": "run-public-v1",
                "output_sha256": digest,
                "row_key": None,
            },
        )
        errors = VALIDATOR.validate_rows([value], {digest: duplicate_report}, mapping=None)
        self.assertTrue(any("public audit output is not valid JSON" in error for error in errors))

        value, output, mapping = mapped_case()
        duplicate_output = output.replace(b'"path":"app.py"', b'"path":"app.py","path":"app.py"', 1)
        self.assertNotEqual(duplicate_output, output)
        digest = hashlib.sha256(duplicate_output).hexdigest()
        value["cli_observation"]["output_sha256"] = digest  # type: ignore[index]
        invocation = cast("list[dict[str, Any]]", mapping["invocations"])[0]
        invocation["output_sha256"] = digest
        errors = VALIDATOR.validate_rows([value], {digest: duplicate_output}, mapping)
        self.assertTrue(any("mapping output is not valid JSON" in error for error in errors))

    def test_cli_ingresses_reject_duplicates_and_invalid_utf8_before_loading_sources(self) -> None:
        unresolved = row(
            outcome="incomplete",
            reason="dynamic_or_missing_evidence",
            cli_observation={
                "status": "not_run",
                "invocation_id": None,
                "output_sha256": None,
                "row_key": None,
            },
        )
        valid_inventory = json.dumps([unresolved]).encode()
        duplicate_inventory = valid_inventory.replace(
            b'"status": "not_run"', b'"status": "not_run", "status": "not_run"', 1
        )
        self.assertNotEqual(duplicate_inventory, valid_inventory)
        cases = (
            (duplicate_inventory, b"{}", "cannot read inventory JSON", "duplicate JSON member"),
            (b"\xff", b"{}", "cannot read inventory JSON", "invalid JSON in inventory"),
            (
                valid_inventory,
                b'{"schema_version":1,"schema_version":1,"invocations":[]}',
                "cannot read mapping/output",
                "duplicate JSON member",
            ),
            (valid_inventory, b"\xff", "cannot read mapping/output", "invalid JSON in mapping"),
        )
        for inventory_bytes, mapping_bytes, context, reason in cases:
            supplied = {"inventory.json": inventory_bytes, "mapping.json": mapping_bytes}

            def read_supplied(path: Path, data: dict[str, bytes] = supplied) -> bytes:
                self.assertIn(str(path), data, "read continued beyond rejected JSON ingress")
                return data[str(path)]

            with (
                patch.object(
                    VALIDATOR.sys,
                    "argv",
                    ["validator.py", "inventory.json", "mapping.json", "outputs", "sources"],
                ),
                patch.object(Path, "read_bytes", autospec=True, side_effect=read_supplied),
                redirect_stderr(StringIO()) as stderr,
            ):
                self.assertEqual(VALIDATOR.main(), 2)
            self.assertIn(context, stderr.getvalue())
            self.assertIn(reason, stderr.getvalue())

    def test_strict_json_bytes_preserve_valid_model_serialization_and_reject_nested_nan(
        self,
    ) -> None:
        report_path = Path(__file__).parents[1] / "fixtures" / "gh97_audit_effect_contracts_v1.json"
        output = report_path.read_bytes()
        digest = hashlib.sha256(output).hexdigest()
        value = row(
            outcome="unsupported",
            reason="other_frozen_reason",
            cli_observation={
                "status": "unsupported",
                "invocation_id": "run-public-v1",
                "output_sha256": digest,
                "row_key": None,
            },
        )
        self.assertEqual(VALIDATOR.validate_rows([value], {digest: output}, mapping=None), [])
        invalid = output.replace(b'"handler_line": 5', b'"handler_line": NaN', 1)
        self.assertNotEqual(output, invalid)
        digest = hashlib.sha256(invalid).hexdigest()
        value["cli_observation"]["output_sha256"] = digest  # type: ignore[index]
        errors = VALIDATOR.validate_rows([value], {digest: invalid}, mapping=None)
        self.assertTrue(any("public audit output is not valid JSON" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
