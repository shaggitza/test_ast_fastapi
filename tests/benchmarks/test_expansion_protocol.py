"""Strict, offline tests for the frozen 50-project expansion protocol."""

from __future__ import annotations

import copy
import hashlib
import json
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from benchmarks.real_world import expansion_protocol as protocol

if TYPE_CHECKING:
    from pytest import MonkeyPatch

_ROOT = Path("benchmarks/real_world/expansion")
_MANIFEST = _ROOT / "projects-50-v1.json"
_LONGLIST = _ROOT / "longlist-60-v1.json"
_LOCK = _ROOT / "pr-lock-100-v1.json"
_CHECKSUMS = _ROOT / "checksums-v1.json"


def _pull(repository: str, number: int, merged_at: str) -> dict[str, Any]:
    digit = f"{number % 16:x}"
    return {
        "number": number,
        "merged_at": merged_at,
        "html_url": f"https://github.com/{repository}/pull/{number}",
        "base": {"sha": digit * 40},
        "head": {"sha": "a" * 40},
        "merge_commit_sha": "b" * 40,
    }


def _lock(
    manifest: dict[str, Any],
    manifest_hash: str,
    longlist: dict[str, Any],
    longlist_hash: str,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for project_index, project in enumerate(manifest["projects"], start=1):
        for offset in range(2):
            number = project_index * 10 + offset
            records.append(
                {
                    **_pull(project["repository"], number, "2026-01-01T00:00:00Z"),
                    "repository": project["repository"],
                    "pr": number,
                    "base_sha": "c" * 40,
                    "head_sha": "d" * 40,
                    "merge_commit_sha": "e" * 40,
                    "review_a": "pending",
                    "review_b": "pending",
                    "adjudication": "pending",
                    "pr_type": "unclassified",
                }
            )
            records[-1].pop("number")
            records[-1].pop("base")
            records[-1].pop("head")
    return {
        "schema_version": 1,
        "manifest_id": manifest["id"],
        "manifest_hash": manifest_hash,
        "longlist_id": longlist["id"],
        "longlist_hash": longlist_hash,
        "collector_hash": protocol._collector_hash(),
        "collected_at": "2026-07-16T00:00:00Z",
        "selection": manifest["policy"]["selection"],
        "records": records,
        "network_budget": {"requests": 50, "response_bytes": 1000},
        "survey_verification": {
            "projects": 50,
            "status": "verified_from_github_api",
        },
    }


def test_frozen_manifest_and_longlist_validate() -> None:
    manifest, digest = protocol.load_manifest(_MANIFEST)
    longlist, longlist_digest = protocol.load_longlist(_LONGLIST, manifest)

    assert digest == "sha256:194afecc671535639cf51b4b98e6fbe2d36a6159c882de1ae2bd3a4df1a28fe0"
    assert len(manifest["projects"]) == 50
    assert len(longlist["selected"]) == 50
    assert len(longlist["excluded"]) == 10
    assert longlist_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.__setitem__("schema_version", True), "schema version"),
        (lambda value: value.__setitem__("required_diversity", {}), "diversity contract"),
        (lambda value: value["policy"].__setitem__("selection", "results-aware"), "policy"),
        (lambda value: value["projects"][0].__setitem__("license_spdx", "invented"), "license"),
        (lambda value: value["projects"][0].__setitem__("github_size_kib", -1), "size"),
        (lambda value: value["projects"][0].__setitem__("unexpected", True), "keys"),
    ],
)
def test_manifest_mutations_fail_closed(mutation: Any, message: str) -> None:
    manifest, _digest = protocol.load_manifest(_MANIFEST)
    candidate = copy.deepcopy(manifest)
    mutation(candidate)

    with pytest.raises(protocol.ExpansionProtocolError, match=message):
        protocol.validate_manifest(candidate)


def test_committed_lock_matches_independent_checksum_profile() -> None:
    payload, digest = protocol.load_lock(_LOCK, _MANIFEST, _LONGLIST, _CHECKSUMS)

    assert len(payload["records"]) == 100
    assert digest == "sha256:6df3dc426888e0c8a97a079dbac8ca48ee421fa8ecd1ce63ddd7bf825a61291f"


def test_bounded_reader_rejects_oversize_before_unbounded_allocation(tmp_path: Path) -> None:
    path = tmp_path / "oversize.json"
    with path.open("wb") as handle:
        handle.seek(protocol._MAX_MANIFEST_BYTES)
        handle.write(b"x")

    with pytest.raises(protocol.ExpansionProtocolError, match="exceeds"):
        protocol.load_manifest(path)


def test_selection_uses_highest_pr_numbers_and_deduplicates_pages(
    monkeypatch: MonkeyPatch,
) -> None:
    repository = "example/project"
    pages = [
        [
            _pull(repository, 7, "2026-01-01T00:00:00Z"),
            _pull(repository, 9, "2026-05-01T00:00:00Z"),
            {**_pull(repository, 10, "2026-06-20T00:00:00Z")},
        ]
    ]

    def fake_json(url: str, token: str, budget: protocol.RequestBudget) -> Any:
        del url, token
        budget.reserve()
        return pages.pop(0)

    monkeypatch.setattr(protocol, "_github_json", fake_json)
    budget = protocol.RequestBudget(started=time.monotonic())

    records = protocol._project_prs(
        repository,
        cutoff=protocol._parse_utc("2026-06-15T00:00:00Z", "cutoff"),
        cap=2,
        token="secret",
        budget=budget,
    )

    assert [record["pr"] for record in records] == [9, 7]
    assert budget.requests == 1


def test_redirect_handler_never_forwards_credentials() -> None:
    handler = protocol._RejectRedirects()
    request = urllib.request.Request(
        "https://api.github.com/repos/example/project",
        headers={"Authorization": "Bearer secret"},
    )

    handler.redirect_request(request, None, 302, "Found", {}, "https://evil.test")


def test_lock_round_trip_and_tampering(tmp_path: Path) -> None:
    manifest, manifest_hash = protocol.load_manifest(_MANIFEST)
    longlist, longlist_hash = protocol.load_longlist(_LONGLIST, manifest)
    payload = _lock(manifest, manifest_hash, longlist, longlist_hash)
    protocol.validate_lock(payload, manifest, manifest_hash, longlist, longlist_hash)
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    raw = path.read_bytes()
    lock_hash = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    checksums = tmp_path / "checksums.json"
    checksums.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "id": "oss-expansion-checksums-v1",
                "manifest_id": manifest["id"],
                "manifest_hash": manifest_hash,
                "longlist_hash": longlist_hash,
                "collector_hash": protocol._collector_hash(),
                "lock_hash": lock_hash,
            }
        ),
        encoding="utf-8",
    )

    loaded, digest = protocol.load_lock(path, _MANIFEST, _LONGLIST, checksums)

    assert len(loaded["records"]) == 100
    assert digest == lock_hash
    payload["records"][0]["html_url"] = "https://example.test/not-github"
    with pytest.raises(protocol.ExpansionProtocolError, match="URL"):
        protocol.validate_lock(payload, manifest, manifest_hash, longlist, longlist_hash)
    payload["records"][0]["html_url"] = (
        f"https://github.com/{payload['records'][0]['repository']}/pull/"
        f"{payload['records'][0]['pr']}"
    )
    original_sha = payload["records"][0]["base_sha"]
    replacement = "0" if original_sha[0] != "0" else "1"
    payload["records"][0]["base_sha"] = replacement + original_sha[1:]
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(protocol.ExpansionProtocolError, match="lock_hash"):
        protocol.load_lock(path, _MANIFEST, _LONGLIST, checksums)


def test_no_clobber_publication_is_atomic(tmp_path: Path) -> None:
    output = tmp_path / "frozen.json"
    protocol._publish_no_clobber(output, {"first": True})

    with pytest.raises(protocol.ExpansionProtocolError, match="overwrite"):
        protocol._publish_no_clobber(output, {"second": True})

    assert json.loads(output.read_text(encoding="utf-8")) == {"first": True}
    assert not list(tmp_path.glob(".frozen.json.*"))
