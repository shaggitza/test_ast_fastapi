"""Validation for pinned expanded-corpus candidate manifests."""

import json
import re
from pathlib import Path

_SHA = re.compile(r"^[0-9a-f]{40}$")


def test_mcp_expansion_candidates_are_pinned_and_unique() -> None:
    path = Path("benchmarks/real_world/expansion/mcp-v1.json")
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == 1
    assert payload["adapter"] == "mcp-v1"
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
