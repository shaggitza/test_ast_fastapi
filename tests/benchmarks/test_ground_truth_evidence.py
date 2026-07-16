from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.evidence import (
    EvidenceBudget,
    GitEvidenceValidator,
    collision_resistant_cache_name,
)
from benchmarks.real_world.ground_truth_v2.schema import EvidenceEdge, EvidenceLocation
from tests.benchmarks.ground_truth_helpers import (
    BASE,
    BLOB,
    TARGET,
    TREE1,
    TREE2,
    edge,
    location,
)


def fake_runner(cache: Path, args: Sequence[str]) -> bytes:  # noqa: PLR0911 - command fixture dispatch
    del cache
    command = tuple(args)
    if command == ("config", "--get", "remote.origin.url"):
        return b"https://github.com/owner/repo.git\n"
    if command[0] == "rev-parse" and command[1].endswith("^{commit}"):
        return command[1][:-9].encode() + b"\n"
    if command == ("rev-parse", f"{TARGET}^{{tree}}"):
        return TREE2.encode() + b"\n"
    if command == ("rev-parse", f"{BASE}^{{tree}}"):
        return TREE1.encode() + b"\n"
    if command[0] == "ls-tree":
        return f"100644 blob {BLOB}\tapp.py\0".encode()
    if command == ("cat-file", "-s", BLOB):
        return b"8\n"
    if command == ("cat-file", "blob", BLOB):
        return b"handler\n"
    if command[0] == "diff":
        return b"diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+handler\n"
    raise AssertionError(command)


def validator(tmp_path: Path, *, budget: EvidenceBudget | None = None) -> GitEvidenceValidator:
    cache = tmp_path / collision_resistant_cache_name("owner/repo")
    cache.mkdir(exist_ok=True)
    return GitEvidenceValidator(
        tmp_path,
        "owner/repo",
        BASE,
        TARGET,
        TREE1,
        TREE2,
        budget=budget,
        runner=fake_runner,
    )


def test_valid_git_identity_blob_range_and_changed_line(tmp_path: Path) -> None:
    evidence = EvidenceEdge.model_validate(edge())
    validator(tmp_path).validate_edges([evidence])


def test_changed_location_accepts_target_addition(tmp_path: Path) -> None:
    changed = EvidenceLocation.model_validate(location())
    validator(tmp_path).validate_changed_location(changed)


def test_changed_location_accepts_baseline_deletion(tmp_path: Path) -> None:
    def deletion_runner(cache: Path, args: Sequence[str]) -> bytes:
        if args[0] == "diff":
            return b"diff --git a/app.py b/app.py\n@@ -1 +0,0 @@\n-handler\n"
        return fake_runner(cache, args)

    payload = location()
    payload["side"] = "baseline"
    payload["commit_sha"] = BASE
    changed = EvidenceLocation.model_validate(payload)
    cache = tmp_path / collision_resistant_cache_name("owner/repo")
    cache.mkdir()
    GitEvidenceValidator(
        tmp_path,
        "owner/repo",
        BASE,
        TARGET,
        TREE1,
        TREE2,
        runner=deletion_runner,
    ).validate_changed_location(changed)


def test_changed_location_reuses_parsed_hunks(tmp_path: Path) -> None:
    diff_calls = 0

    def counting_runner(cache: Path, args: Sequence[str]) -> bytes:
        nonlocal diff_calls
        if args[0] == "diff":
            diff_calls += 1
        return fake_runner(cache, args)

    changed = EvidenceLocation.model_validate(location())
    cache = tmp_path / collision_resistant_cache_name("owner/repo")
    cache.mkdir()
    evidence_validator = GitEvidenceValidator(
        tmp_path,
        "owner/repo",
        BASE,
        TARGET,
        TREE1,
        TREE2,
        runner=counting_runner,
    )
    evidence_validator.validate_changed_location(changed)
    evidence_validator.validate_changed_location(changed)
    assert diff_calls == 1


def test_changed_location_rejects_unchanged_range(tmp_path: Path) -> None:
    def unchanged_runner(cache: Path, args: Sequence[str]) -> bytes:
        if args[0] == "diff":
            return b""
        return fake_runner(cache, args)

    changed = EvidenceLocation.model_validate(location())
    cache = tmp_path / collision_resistant_cache_name("owner/repo")
    cache.mkdir()
    evidence_validator = GitEvidenceValidator(
        tmp_path,
        "owner/repo",
        BASE,
        TARGET,
        TREE1,
        TREE2,
        runner=unchanged_runner,
    )
    with pytest.raises(GroundTruthError, match="does not overlap"):
        evidence_validator.validate_changed_location(changed)


def test_wrong_commit_and_budget_fail_closed(tmp_path: Path) -> None:
    payload = edge()
    payload["from_location"]["commit_sha"] = BASE
    evidence = EvidenceEdge.model_validate(payload)
    with pytest.raises(GroundTruthError, match="wrong snapshot"):
        validator(tmp_path).validate_edges([evidence])
    evidence = EvidenceEdge.model_validate(edge())
    with pytest.raises(GroundTruthError, match="budget"):
        validator(tmp_path, budget=EvidenceBudget(max_commands=1)).validate_edges([evidence])
