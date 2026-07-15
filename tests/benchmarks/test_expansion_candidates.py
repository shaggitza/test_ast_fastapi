"""Validation for pinned expanded-corpus candidate manifests."""

import json
import re
from pathlib import Path

import pytest

_SHA = re.compile(r"^[0-9a-f]{40}$")


@pytest.mark.parametrize("adapter", ["mcp-v1", "workers-v1"])
def test_expansion_candidates_are_pinned_and_unique(adapter: str) -> None:
    path = Path(f"benchmarks/real_world/expansion/{adapter}.json")
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == 1
    assert payload["adapter"] == adapter
    entries = payload["entries"]
    assert len(entries) >= 2
    identities = {(entry["repository"], entry["pr"]) for entry in entries}
    assert len(identities) == len(entries)
    for entry in entries:
        assert _SHA.fullmatch(entry["parent_sha"])
        assert _SHA.fullmatch(entry["merge_sha"])
        assert entry["url"] == (f"https://github.com/{entry['repository']}/pull/{entry['pr']}")
        assert entry["root"]
        assert entry["shape"]
        assert entry["expected_inventory"] in {
            "established",
            "conditional_or_unavailable",
        }


def test_worker_adapter_survey_has_fifty_pinned_unique_projects() -> None:
    path = Path("benchmarks/real_world/surveys/worker-adapters-v1.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload["entries"]

    assert payload["schema_version"] == 1
    assert len(entries) == 50
    assert len({entry["repository"] for entry in entries}) == 50
    represented = {entry["adapter_candidate"] for entry in entries}
    assert represented == {"apscheduler", "arq", "celery", "click", "rq", "typer"}
    for entry in entries:
        assert _SHA.fullmatch(entry["commit_sha"])
        assert entry["path"]
        assert "language:python" in entry["query"]
        assert entry["evidence_url"].startswith(
            f"https://github.com/{entry['repository']}/blob/{entry['commit_sha']}/"
        )
