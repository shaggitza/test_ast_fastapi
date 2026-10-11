"""R6 evaluator protocol and provenance controls."""

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
from benchmarks.real_world import evaluate_nonpython_r6 as evaluator

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "benchmarks/real_world/nonpython_v1"


def test_r6_pins_exact_scanner_commit_and_module_hashes() -> None:
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


def test_archive_uses_hash_pinned_bundle_when_commit_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client_hash, deployment_hash = evaluator._archive_scanner(
        ROOT, evaluator.SCANNER_COMMIT, tmp_path
    )
    assert client_hash == evaluator.CLIENT_SCANNER_SHA256
    assert deployment_hash == evaluator.DEPLOYMENT_SCANNER_SHA256


@pytest.mark.parametrize(
    "relative",
    [
        "fastapi_endpoint_detector/analyzer/client_observations.py",
        "fastapi_endpoint_detector/models/endpoint.py",
    ],
)
def test_archive_rejects_modified_pinned_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    bundled = tmp_path / "pinned_scanner"
    shutil.copytree(FIXTURE / "pinned_scanner", bundled)
    (bundled / relative).write_bytes(b"counterfeit pinned source\n")
    monkeypatch.setattr(evaluator, "FIXTURE", tmp_path)
    with pytest.raises(evaluator.NonPythonFixtureError, match="source SHA-256 mismatch"):
        evaluator._archive_scanner(ROOT, evaluator.SCANNER_COMMIT, tmp_path / "out")


def test_archive_propagates_invalid_git_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "missing-git-dir"))
    with pytest.raises(subprocess.CalledProcessError):
        evaluator._archive_scanner(ROOT, evaluator.SCANNER_COMMIT, tmp_path)


def test_archive_propagates_git_archive_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def archive_failure(args: list[str], **_kwargs: object) -> SimpleNamespace:
        if args == ["git", "archive", "--format=tar", evaluator.SCANNER_COMMIT]:
            raise subprocess.CalledProcessError(128, args, stderr=b"corrupt object database")
        return SimpleNamespace(stdout=evaluator.SCANNER_COMMIT + "\n")

    monkeypatch.setattr(subprocess, "run", archive_failure)
    with pytest.raises(subprocess.CalledProcessError, match="archive"):
        evaluator._archive_scanner(ROOT, evaluator.SCANNER_COMMIT, tmp_path)


def test_r6_rejects_modified_source_snapshot(tmp_path: Path) -> None:
    fixture = tmp_path / "nonpython_v1"
    shutil.copytree(FIXTURE, fixture)
    source = fixture / "source/khoj_1216/src/interface/obsidian/src/chat_view.ts"
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(evaluator.NonPythonFixtureError, match="SHA-256 mismatch"):
        evaluator.validate_fixture(fixture)


def test_r6_emits_separate_atoms_and_never_guesses_dynamic_origin_or_prefix() -> None:
    result = evaluator.build_result(repo_root=ROOT)
    assert result["schema"] == "gh108-final-acceptance-r6-v1"
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
    assert len(result["acceptance_criteria"]) == 7
    assert result["public_integration"]["status"] == "present in this base"

    case_map = {case["case_id"]: case for case in result["cases"]}
    for case in case_map.values():
        assert case["explicit_established_surface_joins"] == []
        for observation in case["raw_client_observations"]:
            assert observation["normalized_route_identity"] == (
                f"{observation['method']} {observation['raw_route_path']}"
            )
        for atom in case["atoms"]:
            assert all(
                observation["origin"] is None
                for observation in atom.get("matching_observations", [])
            )
    search_atom = case_map["open-webui/open-webui#26405"]["atoms"][0]
    assert search_atom["status"] == "abstained"
    assert search_atom["path"] == "/api/v1/chats/search"
    assert all(
        observation["raw_route_path"] != search_atom["path"]
        for observation in search_atom["matching_observations"]
    )


def test_r6_result_replay_is_byte_deterministic() -> None:
    first = evaluator.build_result(repo_root=ROOT)
    second = evaluator.build_result(repo_root=ROOT)
    first_bytes = (json.dumps(first, indent=2, sort_keys=True) + "\n").encode()
    second_bytes = (json.dumps(second, indent=2, sort_keys=True) + "\n").encode()
    assert first_bytes == second_bytes
    assert hashlib.sha256(first_bytes).hexdigest() == hashlib.sha256(second_bytes).hexdigest()
    proof = first["scanner"]["executed_sources"]
    assert proof["fastapi_endpoint_detector.analyzer.client_observations"]["sha256"] == (
        evaluator.CLIENT_SCANNER_SHA256
    )
    assert proof["fastapi_endpoint_detector.analyzer.deployment_observations"]["sha256"] == (
        evaluator.DEPLOYMENT_SCANNER_SHA256
    )
