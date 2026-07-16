from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING

import pytest
import yaml
from click.testing import CliRunner
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper, ChangeMapperError
from fastapi_endpoint_detector.cli import cli
from fastapi_endpoint_detector.config import AnalysisConfig, Config, load_config
from fastapi_endpoint_detector.models.report import AnalysisReport
from fastapi_endpoint_detector.output.formatters import get_formatter

if TYPE_CHECKING:
    from pathlib import Path


def _project(root: Path) -> tuple[Path, Path]:
    (root / "helpers.py").write_text(
        "def emit(value: int) -> int:\n    return value\n",
        encoding="utf-8",
    )
    (root / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from helpers import emit\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/')\n"
        "def handler() -> int:\n"
        "    return emit(1)\n",
        encoding="utf-8",
    )
    contracts = root / "effects.yaml"
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "evidence",
                    "version": "1.0.0",
                    "provenance": {"kind": "user", "source": "effects.yaml"},
                },
                "contracts": [
                    {
                        "id": "emit",
                        "symbol": f"{root.name}.helpers.emit",
                        "invocation": "function",
                        "operation": "write",
                        "channel": "custom",
                        "resource": {"kind": "argument", "index": 0},
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    diff = root / "change.diff"
    diff.write_text(
        "diff --git a/helpers.py b/helpers.py\n"
        "--- a/helpers.py\n"
        "+++ b/helpers.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def emit(value: int) -> int:\n"
        "-    return value\n"
        "+    return value + 1\n",
        encoding="utf-8",
    )
    return contracts, diff


def _projection(report):
    return [
        candidate.model_dump(mode="json", exclude={"contract_evidence"})
        for candidate in report.candidate_endpoints
    ]


def test_contract_evidence_decorates_existing_candidates_without_changing_impact(
    tmp_path: Path,
) -> None:
    contracts, diff = _project(tmp_path)
    baseline = ChangeMapper(
        app_path=tmp_path,
        config=Config(),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    configured = ChangeMapper(
        app_path=tmp_path,
        config=Config(analysis=AnalysisConfig(effect_contracts=contracts)),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert _projection(configured) == _projection(baseline)
    assert [item.endpoint.identifier for item in configured.affected_endpoints] == [
        item.endpoint.identifier for item in baseline.affected_endpoints
    ]
    assert configured.orphan_changes == baseline.orphan_changes
    assert configured.effect_contract_audit is not None
    assert configured.effect_contract_audit.summary.matched_calls == 1
    assert len(configured.candidate_endpoints) == 1
    evidence = configured.candidate_endpoints[0].contract_evidence
    assert len(evidence) == 1
    assert evidence[0].contract.id == "emit"
    assert evidence[0].status == "declared_reachable"
    assert evidence[0].change_to_call_flow == "not_established"
    assert evidence[0].resource_identity_status == "unavailable"
    assert evidence[0].config_hash == configured.effect_contract_audit.provenance.config_hash
    assert all(
        item.producer.value != "effect_contract"
        for item in configured.candidate_endpoints[0].effect_evidence
    )
    assert configured.candidate_endpoints[0].confidence == (
        baseline.candidate_endpoints[0].confidence
    )


def test_exact_unmatched_contract_adds_no_contract_evidence(tmp_path: Path) -> None:
    contracts, diff = _project(tmp_path)
    document = yaml.safe_load(contracts.read_text(encoding="utf-8"))
    document["contracts"][0]["symbol"] = "other.module.emit"
    contracts.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(analysis=AnalysisConfig(effect_contracts=contracts)),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert len(report.candidate_endpoints) == 1
    assert report.candidate_endpoints[0].contract_evidence == ()
    assert report.effect_contract_audit is not None
    assert report.effect_contract_audit.summary.matched_calls == 0


def test_matched_contract_with_no_diff_candidate_creates_no_candidate(tmp_path: Path) -> None:
    contracts, _diff = _project(tmp_path)
    empty_diff = tmp_path / "empty.diff"
    empty_diff.write_text("", encoding="utf-8")

    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(analysis=AnalysisConfig(effect_contracts=contracts)),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(empty_diff)

    assert report.effect_contract_audit is not None
    assert report.effect_contract_audit.summary.matched_calls == 1
    assert report.candidate_endpoints == []
    assert report.affected_endpoints == []


def test_contract_snapshot_is_loaded_once_from_config(tmp_path: Path) -> None:
    contracts, diff = _project(tmp_path)
    config_path = tmp_path / "detector.yaml"
    config_path.write_text(
        "analysis:\n  effect_contracts: effects.yaml\n",
        encoding="utf-8",
    )
    config = load_config(config_path)
    original = config.load_effect_contract_snapshot()
    contracts.write_text("invalid: [", encoding="utf-8")

    report = ChangeMapper(
        app_path=tmp_path,
        config=config,
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert original is config.load_effect_contract_snapshot()
    assert report.effect_contract_audit is not None
    assert report.effect_contract_audit.provenance.raw_hash == original.raw_hash


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"secure_ast": False}, "secure_ast"),
        ({"secure_ast": True, "use_scip": True}, "mypy backend"),
    ],
)
def test_contract_evidence_rejects_unsupported_analysis_modes(
    tmp_path: Path,
    kwargs: dict[str, bool],
    match: str,
) -> None:
    contracts, _diff = _project(tmp_path)
    config = Config(analysis=AnalysisConfig(effect_contracts=contracts))

    with pytest.raises(ChangeMapperError, match=match):
        ChangeMapper(app_path=tmp_path, config=config, use_cache=False, **kwargs)


def test_report_rejects_forged_or_duplicate_contract_evidence(tmp_path: Path) -> None:
    contracts, diff = _project(tmp_path)
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(analysis=AnalysisConfig(effect_contracts=contracts)),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    original = report.model_dump(mode="json")

    mutations = []
    forged_call = copy.deepcopy(original)
    forged_call["candidate_endpoints"][0]["contract_evidence"][0]["call_location"]["file_path"] = (
        "forged.py"
    )
    mutations.append(forged_call)
    forged_resolver = copy.deepcopy(original)
    forged_resolver["candidate_endpoints"][0]["contract_evidence"][0]["resolver"] = "forged"
    mutations.append(forged_resolver)
    duplicate = copy.deepcopy(original)
    duplicate["candidate_endpoints"][0]["contract_evidence"].append(
        copy.deepcopy(duplicate["candidate_endpoints"][0]["contract_evidence"][0])
    )
    mutations.append(duplicate)
    wrong_endpoint = copy.deepcopy(original)
    wrong_endpoint["candidate_endpoints"][0]["endpoint"]["handler"]["file_path"] = "/tmp/forged.py"
    mutations.append(wrong_endpoint)
    forged_affected = copy.deepcopy(original)
    forged_affected["affected_endpoints"][0]["contract_evidence"][0]["contract_hash"] = (
        f"sha256:{'0' * 64}"
    )
    mutations.append(forged_affected)

    for payload in mutations:
        with pytest.raises(ValidationError):
            AnalysisReport.model_validate(payload)

    evidence = report.candidate_endpoints[0].contract_evidence[0]
    with pytest.raises(AttributeError):
        evidence.limitations.append("mutation")  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        report.candidate_endpoints[0].contract_evidence.append(evidence)  # type: ignore[attr-defined]


def test_cli_analyze_enables_contract_evidence_only_with_secure_ast(tmp_path: Path) -> None:
    _contracts, diff = _project(tmp_path)
    config = tmp_path / "detector.yaml"
    config.write_text("analysis:\n  effect_contracts: effects.yaml\n", encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "--config",
            str(config),
            "analyze",
            "--app",
            str(tmp_path),
            "--diff",
            str(diff),
            "--secure-ast",
            "--format",
            "json",
            "--no-cache",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["effect_contract_audit"]["matching_status"] == "complete"
    assert data["candidate_endpoints"][0]["contract_evidence"][0]["status"] == (
        "declared_reachable"
    )


def test_filesystem_preset_attaches_open_handle_and_path_resource_origins(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from pathlib import Path\n"
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/')\n"
        "def handler() -> str:\n"
        "    path = Path('/tmp/a')\n"
        "    text = path.read_text()\n"
        "    with open('/tmp/output', 'w') as handle:\n"
        "        handle.write(text)\n"
        "    return text\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -9,1 +9,1 @@\n"
        "-    text = path.read_text()\n"
        "+    text = path.read_text().strip()\n",
        encoding="utf-8",
    )

    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(analysis=AnalysisConfig(effect_preset="filesystem-v1")),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    audit = report.effect_contract_audit
    assert audit is not None
    matched = {item.contract_id: item for item in audit.occurrences if item.contract_id}
    assert matched["pathlib-read-text"].resource_identity is not None
    assert matched["pathlib-read-text"].resource_identity.status.value == "exact"
    assert len(matched["pathlib-read-text"].resource_identity.value_hashes) == 1
    assert matched["io-text-write"].resource_identity is not None
    assert matched["io-text-write"].resource_identity.status.value == "exact"
    serialized = report.model_dump_json()
    assert "/tmp/a" not in serialized
    assert "/tmp/output" not in serialized


def test_contract_evidence_and_audit_render_in_all_formats(tmp_path: Path) -> None:
    contracts, diff = _project(tmp_path)
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(analysis=AnalysisConfig(effect_contracts=contracts)),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    json_data = json.loads(get_formatter("json").format(report))
    yaml_data = yaml.safe_load(get_formatter("yaml").format(report))
    assert json_data["effect_contract_audit"]["matching_status"] == "complete"
    assert json_data["candidate_endpoints"][0]["contract_evidence"][0]["contract"]["id"] == "emit"
    assert yaml_data["effect_contract_audit"] == json_data["effect_contract_audit"]
    for output_format in ("text", "markdown", "html"):
        rendered = get_formatter(output_format).format(report)
        assert "Declared contract" in rendered or "declared contract" in rendered
        assert "change-to-call flow not established" in rendered
