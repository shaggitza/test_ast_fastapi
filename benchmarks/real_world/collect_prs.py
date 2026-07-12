#!/usr/bin/env python3
"""Collect a reproducible corpus of recent merged PRs from FastAPI projects.

Requires an authenticated GitHub CLI (`gh`). The collector stores immutable PR
and commit identifiers plus changed-file metadata, but not third-party source.
Diffs can be fetched on demand during evaluation from each PR's diff URL.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def gh_json(*args: str) -> Any:
    """Run gh and decode its JSON response."""
    result = subprocess.run(
        ["gh", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def collect_repository(repository: str, limit: int) -> list[dict[str, Any]]:
    """Collect the latest merged PRs and stable metadata for one repository."""
    prs = gh_json(
        "pr",
        "list",
        "--repo",
        repository,
        "--state",
        "merged",
        "--limit",
        str(limit),
        "--json",
        "number,title,url,mergedAt,mergeCommit,baseRefName,headRefName,author",
    )

    corpus: list[dict[str, Any]] = []
    for pr in prs:
        detail = gh_json(
            "pr",
            "view",
            str(pr["number"]),
            "--repo",
            repository,
            "--json",
            "additions,deletions,changedFiles,files,body,commits",
        )
        corpus.append(
            {
                "repository": repository,
                **pr,
                "additions": detail["additions"],
                "deletions": detail["deletions"],
                "changedFiles": detail["changedFiles"],
                "files": detail["files"],
                "body": detail["body"],
                "commits": [commit["oid"] for commit in detail["commits"]],
                "diff_url": f"https://github.com/{repository}/pull/{pr['number']}.diff",
                "ground_truth": {
                    "status": "pending_double_review",
                    "review_a": None,
                    "review_b": None,
                    "adjudicated": None,
                },
            }
        )
    return corpus


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=HERE / "repos.json")
    parser.add_argument("--output", type=Path, default=HERE / "corpus.json")
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    limit = config["prs_per_repository"]
    entries: list[dict[str, Any]] = []
    for repository in config["repositories"]:
        entries.extend(collect_repository(repository["name"], limit))

    output = {
        "schema_version": 1,
        "selection": "Latest N merged PRs returned by GitHub at collection time; no content filtering.",
        "collected_at": datetime.now(UTC).isoformat(),
        "config": config,
        "entries": entries,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(entries)} PRs to {args.output}")


if __name__ == "__main__":
    main()
