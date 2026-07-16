"""Offline safety, completeness, and provenance tests for the 50x50 protocol."""

from __future__ import annotations

import copy
import hashlib
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from benchmarks.real_world import expansion_protocol_v2 as protocol

if TYPE_CHECKING:
    from pytest import MonkeyPatch

_MANIFEST = Path("benchmarks/real_world/expansion/projects-50x50-v2.json")
_PREREGISTRATION = Path("benchmarks/real_world/expansion/checksums-50x50-v2-preregistered.json")


def _timestamp(days: int, seconds: int = 0) -> str:
    value = datetime(2026, 6, 14, tzinfo=timezone.utc) - timedelta(days=days, seconds=seconds)
    return value.isoformat().replace("+00:00", "Z")


def _record(repository: str, rank: int) -> dict[str, Any]:
    number = 1000 - rank
    parent = f"{rank % 16:x}" * 40
    return {
        "rank": rank,
        "pr": number,
        "merged_at": _timestamp(rank),
        "html_url": f"https://github.com/{repository}/pull/{number}",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "merge_commit_sha": "c" * 40,
        "merge_parent_shas": [parent],
        "baseline_sha": parent,
        "target_sha": "b" * 40,
        "baseline_rule": "first_parent_of_merge_commit",
        "target_rule": "head_sha",
        "pull_response_sha256": f"sha256:{'e' * 64}",
        "commit_response_sha256": f"sha256:{'f' * 64}",
        "diff_sha256": f"sha256:{'d' * 64}",
        "diff_bytes": 100 + rank,
        "diff_final_url": f"https://github.com/{repository}/pull/{number}.diff",
        "diff_content_type": "text/plain; charset=utf-8",
        "review_a": "pending",
        "review_b": "pending",
        "adjudication": "pending",
        "pr_type": "unclassified",
    }


def _lock(manifest: dict[str, Any], manifest_hash: str) -> dict[str, Any]:
    projects = []
    for item in manifest["projects"]:
        records = [_record(item["repository"], rank) for rank in range(1, 51)]
        projects.append(
            {
                "repository": item["repository"],
                "status": "complete",
                "repository_created_at": "2010-01-01T00:00:00Z",
                "coverage_start": "2025-01-01T00:00:00Z",
                "coverage_end": manifest["policy"]["merged_before"],
                "selected_count": 50,
                "shortfall_reason": None,
                "records": records,
                "selection_evidence": [
                    {
                        "start": "2025-01-01T00:00:00Z",
                        "end": manifest["policy"]["merged_before"],
                        "total_count": 50,
                        "response_hash": f"sha256:{'a' * 64}",
                        "candidates": [
                            {
                                "merged_at": record["merged_at"],
                                "pr": record["pr"],
                                "html_url": record["html_url"],
                            }
                            for record in records
                        ],
                    }
                ],
                "diagnostics": [],
            }
        )
    return {
        "schema_version": 2,
        "id": "oss-expansion-50x50-lock-v2",
        "manifest_id": manifest["id"],
        "manifest_hash": manifest_hash,
        "collector_hash": protocol.collector_hash(),
        "collected_at": "2026-07-16T13:00:00Z",
        "selection": "merged_at descending, then pull-request number descending",
        "projects": projects,
        "network_budget": {
            "requests": 5000,
            "response_bytes": 1000000,
            "diff_bytes": 500000,
            "elapsed_seconds": 100,
        },
    }


def test_manifest_and_v1_byte_sentinels_validate() -> None:
    manifest, digest = protocol.load_manifest(_MANIFEST)

    protocol.validate_v1_sentinels()
    profile = protocol.load_preregistration(_PREREGISTRATION, digest)
    assert profile["live_lock_status"] == "not_collected"
    assert len(manifest["projects"]) == 50
    assert manifest["policy"]["target_prs_per_project"] == 50
    assert digest.startswith("sha256:")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.__setitem__("schema_version", True),
        lambda value: value["policy"].__setitem__("content_filtering_allowed", True),
        lambda value: value["policy"].__setitem__("target_prs_per_project", 49),
        lambda value: value["sharding"].__setitem__("contiguous_from_cutoff", False),
        lambda value: value["projects"].append(value["projects"][0]),
        lambda value: value["projects"][0].__setitem__("repository", "other/repository"),
    ],
)
def test_manifest_cannot_weaken_its_own_protocol(mutation: Any) -> None:
    manifest, _digest = protocol.load_manifest(_MANIFEST)
    candidate = copy.deepcopy(manifest)
    mutation(candidate)

    with pytest.raises(protocol.CorpusV2Error):
        protocol.validate_manifest(candidate)


def test_complete_shards_select_merged_time_then_pr_tie_break() -> None:
    cutoff = datetime(2026, 6, 15, tzinfo=timezone.utc)
    boundary = cutoff - timedelta(days=1)
    tie = cutoff - timedelta(hours=1)
    shards = [
        protocol.CompleteShard(
            start=boundary,
            end=cutoff,
            total_count=3,
            candidates=(
                protocol.Candidate(tie, 8, "https://github.com/o/r/pull/8"),
                protocol.Candidate(tie, 9, "https://github.com/o/r/pull/9"),
                protocol.Candidate(tie - timedelta(hours=1), 10, "https://github.com/o/r/pull/10"),
            ),
            response_hash=f"sha256:{'a' * 64}",
        )
    ]

    status, selected, coverage = protocol.select_from_complete_shards(
        shards,
        cutoff=cutoff,
        target=2,
        repository_created_at=cutoff - timedelta(days=100),
    )

    assert status == "complete"
    assert [item.number for item in selected] == [9, 8]
    assert coverage == boundary


def test_selection_fails_closed_on_gap_and_proves_underfill() -> None:
    cutoff = datetime(2026, 6, 15, tzinfo=timezone.utc)
    shard = protocol.CompleteShard(
        start=cutoff - timedelta(days=10),
        end=cutoff,
        total_count=0,
        candidates=(),
        response_hash=f"sha256:{'a' * 64}",
    )
    with pytest.raises(protocol.CorpusV2Error, match="repository creation"):
        protocol.select_from_complete_shards(
            [shard],
            cutoff=cutoff,
            target=50,
            repository_created_at=cutoff - timedelta(days=100),
        )
    status, selected, _coverage = protocol.select_from_complete_shards(
        [shard],
        cutoff=cutoff,
        target=50,
        repository_created_at=cutoff - timedelta(days=5),
    )
    assert status == "underfilled"
    assert selected == []


def test_lock_round_trip_authenticates_before_parsing(tmp_path: Path) -> None:
    manifest, manifest_hash = protocol.load_manifest(_MANIFEST)
    payload = _lock(manifest, manifest_hash)
    protocol.validate_lock(payload, manifest, manifest_hash)
    lock_path = tmp_path / "lock.json"
    lock_path.write_text(json.dumps(payload), encoding="utf-8")
    lock_hash = f"sha256:{hashlib.sha256(lock_path.read_bytes()).hexdigest()}"
    checksums = tmp_path / "checksums.json"
    checksums.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "id": "oss-expansion-50x50-checksums-v2",
                "manifest_hash": manifest_hash,
                "collector_hash": protocol.collector_hash(),
                "lock_hash": lock_hash,
            }
        ),
        encoding="utf-8",
    )

    loaded, actual_hash = protocol.load_lock_authenticated(lock_path, _MANIFEST, checksums)
    assert len(loaded["projects"]) == 50
    assert actual_hash == lock_hash

    raw = lock_path.read_text(encoding="utf-8")
    lock_path.write_text(
        raw.replace('"base_sha": "aaaaaaaa', '"base_sha": "0aaaaaaa', 1), encoding="utf-8"
    )
    with pytest.raises(protocol.CorpusV2Error, match="lock_hash"):
        protocol.load_lock_authenticated(lock_path, _MANIFEST, checksums)


def test_underfill_and_unavailable_are_not_interchangeable() -> None:
    manifest, manifest_hash = protocol.load_manifest(_MANIFEST)
    payload = _lock(manifest, manifest_hash)
    project = payload["projects"][0]
    project["status"] = "underfilled"
    project["records"] = project["records"][:3]
    project["selected_count"] = 3
    project["shortfall_reason"] = "history_exhausted"
    project["coverage_start"] = project["repository_created_at"]
    project["selection_evidence"][0]["start"] = project["repository_created_at"]
    project["selection_evidence"][0]["total_count"] = 3
    project["selection_evidence"][0]["candidates"] = project["selection_evidence"][0]["candidates"][
        :3
    ]
    protocol.validate_lock(payload, manifest, manifest_hash)

    project["coverage_start"] = "2025-01-01T00:00:00Z"
    with pytest.raises(protocol.CorpusV2Error, match="underfill"):
        protocol.validate_lock(payload, manifest, manifest_hash)


def test_selection_evidence_recomputes_ranked_records() -> None:
    manifest, manifest_hash = protocol.load_manifest(_MANIFEST)
    payload = _lock(manifest, manifest_hash)
    evidence = payload["projects"][0]["selection_evidence"][0]["candidates"]
    evidence[0]["pr"] += 10000
    evidence[0]["html_url"] = (
        f"https://github.com/{payload['projects'][0]['repository']}/pull/{evidence[0]['pr']}"
    )

    with pytest.raises(protocol.CorpusV2Error, match="records do not match"):
        protocol.validate_lock(payload, manifest, manifest_hash)


def test_diff_hashing_is_bounded() -> None:
    budget = protocol.NetworkBudget(
        max_requests=1,
        max_response_bytes=10,
        max_diff_bytes=5,
        max_total_diff_bytes=10,
        max_wall_seconds=10,
        started=time.monotonic(),
    )
    digest, size = protocol.hash_stream([b"ab", b"cd"], budget)
    assert digest == f"sha256:{hashlib.sha256(b'abcd').hexdigest()}"
    assert size == 4
    with pytest.raises(protocol.CorpusV2Error, match="one diff"):
        protocol.hash_stream([b"123456"], budget)


class _FakeTransport(protocol.GitHubTransport):
    def __init__(self, budget: protocol.NetworkBudget) -> None:
        self.budget = budget
        self.calls = 0

    def repository_created_at(self, repository: str) -> datetime:
        del repository
        self.budget.reserve()
        return datetime(2020, 1, 1, tzinfo=timezone.utc)

    def search_shard(
        self, repository: str, start: datetime, end: datetime
    ) -> protocol.CompleteShard:
        self.calls += 1
        candidates = tuple(
            protocol.Candidate(
                end - timedelta(hours=rank),
                1000 - rank,
                f"https://github.com/{repository}/pull/{1000 - rank}",
            )
            for rank in range(1, 51)
        )
        return protocol.CompleteShard(start, end, 50, candidates, f"sha256:{'a' * 64}")

    def record(self, repository: str, candidate: protocol.Candidate, rank: int) -> dict[str, Any]:
        record = _record(repository, rank)
        for _request in range(3):
            self.budget.reserve()
        self.budget.consume(record["diff_bytes"], diff=True)
        record["pr"] = candidate.number
        record["merged_at"] = candidate.merged_at.isoformat().replace("+00:00", "Z")
        record["html_url"] = candidate.html_url
        return record


def test_project_collection_and_atomic_resume(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    manifest, manifest_hash = protocol.load_manifest(_MANIFEST)
    instances: list[_FakeTransport] = []

    def factory(
        token: str,
        budget: protocol.NetworkBudget,
        timeout: int,
        max_api_response_bytes: int,
        max_rate_limit_wait_seconds: int,
        max_retries_per_request: int,
    ) -> _FakeTransport:
        del (
            token,
            timeout,
            max_api_response_bytes,
            max_rate_limit_wait_seconds,
            max_retries_per_request,
        )
        instance = _FakeTransport(budget)
        instances.append(instance)
        return instance

    monkeypatch.setattr(protocol, "GitHubTransport", factory)
    checkpoints = tmp_path / "checkpoints"
    first_output = tmp_path / "first.json"
    first = protocol.collect_live(
        manifest,
        manifest_hash,
        token="secret",
        checkpoint_dir=checkpoints,
        output=first_output,
    )
    assert len(first["projects"]) == 50
    assert all(project["status"] == "complete" for project in first["projects"])
    assert sum(instance.calls for instance in instances) == 50

    instances.clear()
    second_output = tmp_path / "second.json"
    second = protocol.collect_live(
        manifest,
        manifest_hash,
        token="secret",
        checkpoint_dir=checkpoints,
        output=second_output,
    )
    assert len(second["projects"]) == 50
    assert sum(instance.calls for instance in instances) == 0

    checkpoint = checkpoints / "01.json"
    checkpoint.write_bytes(checkpoint.read_bytes() + b" ")
    with pytest.raises(protocol.CorpusV2Error, match="checkpoint checksum"):
        protocol.collect_live(
            manifest,
            manifest_hash,
            token="secret",
            checkpoint_dir=checkpoints,
            output=tmp_path / "third.json",
        )


def test_semantically_invalid_checkpoint_fails_before_transport(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    manifest, manifest_hash = protocol.load_manifest(_MANIFEST)
    project = _lock(manifest, manifest_hash)["projects"][0]
    project["records"] = []
    project["selected_count"] = 0
    checkpoint = {
        "schema_version": 2,
        "collector_hash": protocol.collector_hash(),
        "index": 1,
        "project": project,
        "network_budget": {
            "requests": 1,
            "response_bytes": 0,
            "diff_bytes": 0,
            "elapsed_seconds": 1,
        },
    }
    checkpoint_dir = tmp_path / "checkpoints"
    checkpoint_dir.mkdir()
    protocol._write_checkpoint(
        checkpoint_dir,
        1,
        checkpoint,
        max_bytes=manifest["bounds"]["max_checkpoint_bytes"],
    )

    def forbidden_transport(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("transport constructed before checkpoint validation")

    monkeypatch.setattr(protocol, "GitHubTransport", forbidden_transport)
    with pytest.raises(protocol.CorpusV2Error, match="complete project"):
        protocol.collect_live(
            manifest,
            manifest_hash,
            token="secret",
            checkpoint_dir=checkpoint_dir,
            output=tmp_path / "lock.json",
        )


def test_resumed_wall_budget_is_rejected_before_transport(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    manifest, manifest_hash = protocol.load_manifest(_MANIFEST)
    project = _lock(manifest, manifest_hash)["projects"][0]
    project.update(
        status="unavailable",
        repository_created_at=None,
        coverage_start=None,
        coverage_end=None,
        selected_count=0,
        shortfall_reason="repository_unavailable",
        records=[],
        selection_evidence=[],
        diagnostics=["repository unavailable"],
    )
    checkpoint = {
        "schema_version": 2,
        "collector_hash": protocol.collector_hash(),
        "index": 1,
        "project": project,
        "network_budget": {
            "requests": 1,
            "response_bytes": 0,
            "diff_bytes": 0,
            "elapsed_seconds": manifest["bounds"]["max_wall_seconds"],
        },
    }
    checkpoint_dir = tmp_path / "checkpoints"
    checkpoint_dir.mkdir()
    protocol._write_checkpoint(
        checkpoint_dir,
        1,
        checkpoint,
        max_bytes=manifest["bounds"]["max_checkpoint_bytes"],
    )

    def forbidden_transport(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("transport constructed after exhausted resume budget")

    monkeypatch.setattr(protocol, "GitHubTransport", forbidden_transport)
    with pytest.raises(protocol.CorpusV2Error, match="no aggregate budget"):
        protocol.collect_live(
            manifest,
            manifest_hash,
            token="secret",
            checkpoint_dir=checkpoint_dir,
            output=tmp_path / "lock.json",
        )


def test_record_rejects_mismatched_merge_commit_response() -> None:
    class RecordTransport(protocol.GitHubTransport):
        def __init__(self) -> None:
            self.calls = 0

        def get_json(self, url: str) -> dict[str, Any]:
            del url
            self.calls += 1
            if self.calls == 1:
                return {
                    "number": 7,
                    "html_url": "https://github.com/o/r/pull/7",
                    "merged_at": "2026-06-01T12:00:00Z",
                    "base": {"sha": "a" * 40},
                    "head": {"sha": "b" * 40},
                    "merge_commit_sha": "c" * 40,
                }
            return {"sha": "d" * 40, "parents": [{"sha": "e" * 40}]}

        def hash_diff(self, repository: str, number: int) -> tuple[str, int, str, str]:
            raise AssertionError(f"diff reached for mismatched identity: {repository}#{number}")

    candidate = protocol.Candidate(
        datetime(2026, 6, 1, 12, tzinfo=timezone.utc),
        7,
        "https://github.com/o/r/pull/7",
    )
    with pytest.raises(protocol.CorpusV2Error, match="response SHA"):
        RecordTransport().record("o/r", candidate, 1)


def test_search_shard_requires_stable_complete_cardinality() -> None:
    budget = protocol.NetworkBudget(10, 100000, 1000, 1000, 10)
    transport = object.__new__(protocol.GitHubTransport)
    transport.budget = budget
    start = datetime(2026, 6, 1, tzinfo=timezone.utc)
    end = datetime(2026, 6, 2, tzinfo=timezone.utc)
    payload = {
        "total_count": 1,
        "incomplete_results": False,
        "items": [
            {
                "number": 7,
                "html_url": "https://github.com/o/r/pull/7",
                "pull_request": {"merged_at": "2026-06-01T12:00:00Z"},
            }
        ],
    }
    transport.get_json = lambda _url: payload  # type: ignore[assignment]
    shard = transport.search_shard("o/r", start, end)
    assert shard.total_count == 1
    payload["incomplete_results"] = True
    with pytest.raises(protocol.CorpusV2Error, match="incomplete"):
        transport.search_shard("o/r", start, end)


def test_diff_redirect_strips_credentials_and_binds_exact_pr() -> None:
    handler = protocol._SafeDiffRedirects("o/r", 1)
    request = urllib.request.Request(
        "https://github.com/o/r/pull/1.diff",
        headers={"Authorization": "Bearer secret", "Accept": "text/plain"},
    )
    redirected = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://patch-diff.githubusercontent.com/raw/o/r/pull/1.diff",
    )
    assert redirected.get_header("Authorization") is None
    assert redirected.get_header("Accept") == "text/plain"
    invalid = (
        "https://evil.test/x",
        "https://github.com/login",
        "https://github.com/other/repo/pull/1.diff",
        "https://github.com/o/r/pull/2.diff",
        "https://github.com/o/r/pull/1.diff?other=1",
        "https://user:pass@github.com/o/r/pull/1.diff",
        "https://patch-diff.githubusercontent.com/raw/o/r/pull/../2.diff",
    )
    for url in invalid:
        with pytest.raises(protocol.CorpusV2Error, match="exact PR identity"):
            handler.redirect_request(request, None, 302, "Found", {}, url)


def test_repository_metadata_failure_is_terminal_unavailable() -> None:
    budget = protocol.NetworkBudget(10, 1000, 100, 100, 10)
    transport = _FakeTransport(budget)

    def unavailable(repository: str) -> datetime:
        raise protocol.CorpusV2Error(f"repository unavailable: {repository}")

    transport.repository_created_at = unavailable  # type: ignore[method-assign]
    result = protocol.collect_project(
        transport,
        "o/r",
        cutoff=datetime(2026, 6, 15, tzinfo=timezone.utc),
        target=50,
        window_days=30,
        max_shards=10,
        max_candidates=100,
    )

    assert result["status"] == "unavailable"
    assert result["shortfall_reason"] == "repository_unavailable"
    assert result["repository_created_at"] is None
    assert result["coverage_start"] is None
    assert result["records"] == []
    assert result["diagnostics"]


def test_unavailable_lock_rejects_partial_records_or_missing_evidence() -> None:
    manifest, manifest_hash = protocol.load_manifest(_MANIFEST)
    payload = _lock(manifest, manifest_hash)
    project = payload["projects"][0]
    project.update(
        status="unavailable",
        repository_created_at=None,
        coverage_start=None,
        coverage_end=None,
        selected_count=0,
        shortfall_reason="repository_unavailable",
        records=[],
        selection_evidence=[],
        diagnostics=["repository unavailable"],
    )
    protocol.validate_lock(payload, manifest, manifest_hash)

    project["records"] = [_record(project["repository"], 1)]
    project["selected_count"] = 1
    with pytest.raises(protocol.CorpusV2Error, match="unavailable project must be empty"):
        protocol.validate_lock(payload, manifest, manifest_hash)
    project["records"] = []
    project["selected_count"] = 0
    project["diagnostics"] = []
    with pytest.raises(protocol.CorpusV2Error, match="diagnostics"):
        protocol.validate_lock(payload, manifest, manifest_hash)
    project["diagnostics"] = ["repository unavailable"]
    payload["network_budget"]["requests"] = 0
    with pytest.raises(protocol.CorpusV2Error, match="one repository lookup"):
        protocol.validate_lock(payload, manifest, manifest_hash)


def test_budget_rejection_does_not_mutate_counters() -> None:
    budget = protocol.NetworkBudget(2, 3, 3, 3, 10)
    budget.consume(3)
    with pytest.raises(protocol.CorpusV2Error, match="response-byte"):
        budget.consume(1)
    assert budget.response_bytes == 3
    assert budget.diff_bytes == 0

    diff_budget = protocol.NetworkBudget(2, 10, 3, 3, 10)
    diff_budget.consume(3, diff=True)
    with pytest.raises(protocol.CorpusV2Error, match="total diff-byte"):
        diff_budget.consume(1, diff=True)
    assert diff_budget.response_bytes == 3
    assert diff_budget.diff_bytes == 3


def test_search_dense_response_requires_single_response_split() -> None:
    budget = protocol.NetworkBudget(10, 100000, 1000, 1000, 10)
    transport = object.__new__(protocol.GitHubTransport)
    transport.budget = budget
    transport.get_json = lambda _url: {  # type: ignore[assignment]
        "total_count": 101,
        "incomplete_results": False,
        "items": [],
    }
    with pytest.raises(protocol.DenseShardError, match="one-response"):
        transport.search_shard(
            "o/r",
            datetime(2026, 6, 1, tzinfo=timezone.utc),
            datetime(2026, 6, 2, tzinfo=timezone.utc),
        )


def test_atomic_publication_refuses_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "lock.json"
    protocol._publish_no_clobber(output, {"first": True})
    with pytest.raises(protocol.CorpusV2Error, match="overwrite"):
        protocol._publish_no_clobber(output, {"second": True})
    assert json.loads(output.read_text(encoding="utf-8")) == {"first": True}


def test_blocking_api_read_is_interrupted_at_wall_deadline() -> None:
    class SlowResponse:
        def __enter__(self) -> SlowResponse:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def geturl(self) -> str:
            return "https://api.github.com/repos/o/r"

        def read(self, _size: int) -> bytes:
            time.sleep(2)
            return b"{}"

    class SlowOpener:
        def open(self, request: urllib.request.Request, timeout: float) -> SlowResponse:
            del request, timeout
            return SlowResponse()

    budget = protocol.NetworkBudget(2, 1000, 100, 100, 1)
    transport = protocol.GitHubTransport("secret", budget, 30, 1000, 10, 0)
    transport._api_opener = SlowOpener()  # type: ignore[assignment]
    started = time.monotonic()
    with pytest.raises(protocol.CorpusV2Error, match="request failed"):
        transport.get_json("https://api.github.com/repos/o/r")
    assert time.monotonic() - started < 1.5


def test_blocking_diff_read_is_interrupted_at_wall_deadline(
    monkeypatch: MonkeyPatch,
) -> None:
    class SlowDiffResponse:
        def __init__(self) -> None:
            self.headers = Message()
            self.headers["Content-Type"] = "text/plain; charset=utf-8"

        def __enter__(self) -> SlowDiffResponse:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def geturl(self) -> str:
            return "https://patch-diff.githubusercontent.com/raw/o/r/pull/1.diff"

        def read(self, _size: int) -> bytes:
            time.sleep(2)
            return b"diff"

    class SlowDiffOpener:
        def open(self, request: urllib.request.Request, timeout: float) -> SlowDiffResponse:
            del request, timeout
            return SlowDiffResponse()

    budget = protocol.NetworkBudget(2, 1000, 100, 100, 1)
    transport = protocol.GitHubTransport("secret", budget, 30, 1000, 10, 0)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args: SlowDiffOpener())
    started = time.monotonic()
    with pytest.raises(protocol.CorpusV2Error, match="diff request failed"):
        transport.hash_diff("o/r", 1)
    assert time.monotonic() - started < 1.5


def test_rate_limit_delay_is_bounded() -> None:
    budget = protocol.NetworkBudget(10, 1000, 100, 100, 100)
    transport = protocol.GitHubTransport("secret", budget, 1, 1000, 10, 2)
    headers = Message()
    headers["Retry-After"] = "4"
    error = urllib.error.HTTPError(
        "https://api.github.com/search/issues",
        429,
        "limited",
        headers,
        None,
    )
    assert transport._rate_limit_delay(error, 0) == 4
    long_headers = Message()
    long_headers["Retry-After"] = "11"
    too_long = urllib.error.HTTPError(
        error.url,
        429,
        "limited",
        long_headers,
        None,
    )
    with pytest.raises(protocol.CorpusV2Error, match="frozen bound"):
        transport._rate_limit_delay(too_long, 0)
