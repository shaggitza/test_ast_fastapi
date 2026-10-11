"""R8 evaluator protocol and provenance controls."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from benchmarks.real_world import evaluate_nonpython_r8 as evaluator

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "benchmarks/real_world/nonpython_v1"


def test_r8_pins_exact_scanner_commit_and_module_hashes() -> None:
    assert evaluator._require_trusted_scanner_commit(evaluator.SCANNER_COMMIT) == (
        "d4eec140bed84d3ff8cea8374f7f9e589b0e6def"
    )
    for counterfeit in (
        "84efc3d877c2d93a25bdd2c625120e6a6d918139",
        "1d9242d0d1d411b529c3227918aa2d05e98e8943",
        "0" * 40,
    ):
        with pytest.raises(evaluator.NonPythonFixtureError, match="approved immutable"):
            evaluator._require_trusted_scanner_commit(counterfeit)


def test_archive_rejects_counterfeit_scanner_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"counterfeit scanner module\n"
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        for relative in (evaluator.CLIENT_SCANNER_PATH, evaluator.DEPLOYMENT_SCANNER_PATH):
            info = tarfile.TarInfo(relative)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))

    def fake_git(args: list[str], **_kwargs: object) -> SimpleNamespace:
        if args[1] == "rev-parse":
            return SimpleNamespace(stdout=evaluator.SCANNER_COMMIT + "\n")
        return SimpleNamespace(stdout=archive_buffer.getvalue())

    monkeypatch.setattr(subprocess, "run", fake_git)
    with pytest.raises(evaluator.NonPythonFixtureError, match="module SHA-256"):
        evaluator._archive_scanner(ROOT, evaluator.SCANNER_COMMIT, tmp_path)


def test_r8_rejects_modified_source_snapshot(tmp_path: Path) -> None:
    fixture = tmp_path / "nonpython_v1"
    shutil.copytree(FIXTURE, fixture)
    source = fixture / "source/khoj_1216/src/interface/obsidian/src/chat_view.ts"
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(evaluator.NonPythonFixtureError, match="SHA-256 mismatch"):
        evaluator.validate_fixture(fixture)


def test_r8_emits_separate_atoms_and_never_guesses_dynamic_origin_or_prefix() -> None:
    result = evaluator.build_result(repo_root=ROOT)
    assert result["schema"] == "gh108-audited-callsite-repair-r8-v1"
    assert result["scope_units"] == {
        "audited_pr_count": 6,
        "client_route_atom_count": 8,
        "conditional_deployment_atom_count": 1,
        "total_audited_nonpython_atom_count": 9,
    }
    assert result["truth_status"] == "reviewed_historical_atoms_provisional_not_canonical_truth"
    assert result["scanner"]["repository_commit"] == evaluator.SCANNER_COMMIT
    assert result["scanner"]["client_source_sha256"] == evaluator.CLIENT_SCANNER_SHA256
    assert result["scanner"]["deployment_source_sha256"] == evaluator.DEPLOYMENT_SCANNER_SHA256
    assert result["verified_source_file_count"] == 25
    assert result["verified_diff_count"] == 6
    assert len(result["verified_licenses"]) == 6
    assert len(result["acceptance_criteria"]) == 8
    assert result["public_integration"]["status"] == "present in this base"

    case_map = {case["case_id"]: case for case in result["cases"]}
    for case in case_map.values():
        assert case["explicit_established_surface_joins"] == []
        for observation in case["raw_client_observations"]:
            assert observation["normalized_route_identity"] == (
                f"{observation['method']} {observation['raw_route_path']}"
            )
        for atom in case["atoms"]:
            if case["mode"] == "docker_env_subprocess":
                continue
            assert all(
                observation["origin"] is None
                for observation in atom.get("raw_same_route_observations", [])
            )
            observations = atom["audited_callsite_observations"]
            if observations:
                if atom["surface_id"] in case["explicit_established_surface_joins"]:
                    assert atom["origin_attestation_missing"] is False
                    assert atom["origin_join_status"] == "joined"
                else:
                    assert atom["origin_attestation_missing"] is True
                    assert atom["origin_join_status"] == "unjoined_origin_unattested"
            else:
                assert atom["origin_attestation_missing"] is False
                assert atom["origin_join_status"] == atom["audited_callsite_status"]
    khoj_atom = case_map["khoj-ai/khoj#1216"]["atoms"][0]
    assert khoj_atom["audited_callsite_locations"][0]["start_line"] == 960
    assert khoj_atom["audited_callsite_locations"][0]["end_line"] == 974
    assert khoj_atom["audited_callsite_status"] == "unobserved_by_scanner"
    assert khoj_atom["audited_callsite_observations"] == []
    assert khoj_atom["audited_callsite_locations"][0]["source_sha256"] == (
        "c6c301fa13f511f7eaad1afd207e721f751c71277bce06c9a7da04091e5a2c5f"
    )
    assert any(
        observation["line"] == 1492 for observation in khoj_atom["raw_same_route_observations"]
    )
    assert sum(len(case["raw_client_observations"]) for case in case_map.values()) == 35
    search_atom = case_map["open-webui/open-webui#26405"]["atoms"][0]
    assert search_atom["status"] == "abstained"
    assert search_atom["path"] == "/api/v1/chats/search"
    assert all(
        observation["raw_route_path"] != search_atom["path"]
        for observation in search_atom["raw_same_route_observations"]
    )
    assert search_atom["audited_callsite_status"] == "unresolved_audit_location"
    assert search_atom["audited_callsite_locations"] == []
    langflow = case_map["langflow-ai/langflow#13992"]["atoms"][0]
    assert langflow["runtime_observed"] is False
    assert len(langflow["observation_refs"]["docker"]) == 36
    assert (
        sum(
            observation["certainty"] == "exact"
            for observation in case_map["langflow-ai/langflow#13992"]["raw_deployment_observations"]
        )
        == 3
    )
    assert (
        sum(
            observation["certainty"] == "uncertain"
            for observation in case_map["langflow-ai/langflow#13992"]["raw_deployment_observations"]
        )
        == 33
    )


def test_audited_location_resolution_rejects_bad_path_and_ranges() -> None:
    source = {"src/client.ts": "one\ntwo\nthree\n"}
    hashes = {"src/client.ts": hashlib.sha256(source["src/client.ts"].encode()).hexdigest()}
    assert (
        evaluator._audited_locations("src/client.ts:1-2", {"src/client.ts"}, source, hashes)[0][
            "end_line"
        ]
        == 2
    )
    for evidence in ("src/client.ts:0-2", "src/client.ts:3-2", "src/client.ts:2-5"):
        assert evaluator._audited_locations(evidence, {"src/client.ts"}, source, hashes) == []
    assert evaluator._audited_locations("src/other.ts:1-2", {"src/client.ts"}, source, hashes) == []
    assert (
        evaluator._audited_locations("src/client.ts:1 onward", {"src/client.ts"}, source, hashes)
        == []
    )


def test_r8_result_replay_is_byte_deterministic() -> None:
    first = evaluator.build_result(repo_root=ROOT)
    second = evaluator.build_result(repo_root=ROOT)
    first_bytes = (json.dumps(first, indent=2, sort_keys=True) + "\n").encode()
    second_bytes = (json.dumps(second, indent=2, sort_keys=True) + "\n").encode()
    assert first_bytes == second_bytes
    assert hashlib.sha256(first_bytes).hexdigest() == hashlib.sha256(second_bytes).hexdigest()


def test_r8_limits_acceptance_to_direct_extractor_evidence() -> None:
    result = evaluator.build_result(repo_root=ROOT)
    assert result["acceptance_claim"] == (
        "R8/R9 bounded source observations recorded; "
        "subprocess criterion unverified; GH108 full acceptance remains open"
    )
    fanout = next(
        item
        for item in result["acceptance_criteria"]
        if item["criterion"] == "no_cross_language_global_url_fanout"
    )
    assert fanout["finding"].startswith("UNVERIFIED:")
    assert fanout["source_refs"] == []

    subprocess_criterion = next(
        item
        for item in result["acceptance_criteria"]
        if item["criterion"] == "subprocess_observations"
    )
    assert subprocess_criterion["finding"].startswith("UNVERIFIED:")
    assert subprocess_criterion["source_refs"] == []
    langflow = next(
        case for case in result["cases"] if case["case_id"] == "langflow-ai/langflow#13992"
    )
    assert langflow["raw_subprocess_observations"] == []
    assert langflow["atoms"][0]["observation_refs"]["subprocess"] == []


def test_r8_committed_artifact_does_not_claim_subprocess_observations() -> None:
    artifact = json.loads((FIXTURE / "results/evaluation-r8.json").read_text())
    subprocess_criterion = next(
        item
        for item in artifact["acceptance_criteria"]
        if item["criterion"] == "subprocess_observations"
    )
    assert subprocess_criterion["finding"].startswith("UNVERIFIED:")
    assert subprocess_criterion["source_refs"] == []
    assert "subprocess criterion unverified" in artifact["acceptance_claim"]
    langflow = next(
        case for case in artifact["cases"] if case["case_id"] == "langflow-ai/langflow#13992"
    )
    assert langflow["raw_subprocess_observations"] == []
    assert langflow["atoms"][0]["observation_refs"]["subprocess"] == []
