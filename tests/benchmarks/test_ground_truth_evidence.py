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
from benchmarks.real_world.ground_truth_v2.schema import EvidenceEdge
from tests.benchmarks.ground_truth_helpers import BASE, BLOB, TARGET, TREE1, TREE2, edge


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


def test_wrong_commit_and_budget_fail_closed(tmp_path: Path) -> None:
    payload = edge()
    payload["from_location"]["commit_sha"] = BASE
    evidence = EvidenceEdge.model_validate(payload)
    with pytest.raises(GroundTruthError, match="wrong snapshot"):
        validator(tmp_path).validate_edges([evidence])
    evidence = EvidenceEdge.model_validate(edge())
    with pytest.raises(GroundTruthError, match="budget"):
        validator(tmp_path, budget=EvidenceBudget(max_commands=1)).validate_edges([evidence])
