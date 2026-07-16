"""Offline, resource-bounded validation of evidence against immutable Git objects."""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import TYPE_CHECKING

from . import GroundTruthError

if TYPE_CHECKING:
    from .schema import EvidenceEdge, EvidenceLocation

_MAX_OUTPUT = 4 * 1024 * 1024
_HUNK = re.compile(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class EvidenceBudget:
    max_commands: int = 5000
    max_unique_blobs: int = 2000
    max_blob_bytes: int = 100 * 1024 * 1024
    max_lines: int = 5_000_000
    max_wall_seconds: int = 600
    commands: int = 0
    unique_blobs: int = 0
    blob_bytes: int = 0
    lines: int = 0
    started: float = 0.0

    def start(self) -> None:
        if self.started == 0:
            self.started = time.monotonic()

    def consume_command(self) -> None:
        self.start()
        self.commands += 1
        if (
            self.commands > self.max_commands
            or time.monotonic() - self.started > self.max_wall_seconds
        ):
            raise GroundTruthError("Git evidence command/wall budget exceeded")

    def check_wall(self) -> None:
        self.start()
        if time.monotonic() - self.started > self.max_wall_seconds:
            raise GroundTruthError("Git evidence command/wall budget exceeded")

    def consume_blob(self, size: int, lines: int) -> None:
        self.unique_blobs += 1
        self.blob_bytes += size
        self.lines += lines
        if (
            self.unique_blobs > self.max_unique_blobs
            or self.blob_bytes > self.max_blob_bytes
            or self.lines > self.max_lines
        ):
            raise GroundTruthError("Git evidence blob/byte/line budget exceeded")


GitRunner = Callable[[Path, Sequence[str]], bytes]


def collision_resistant_cache_name(repository: str) -> str:
    """Return a filesystem-safe cache name that retains full repository identity."""
    slug = repository.replace("/", "--")
    return f"{slug}-{hashlib.sha256(repository.casefold().encode()).hexdigest()[:16]}.git"


class GitEvidenceValidator:
    """Validate paths, blobs, ranges, chains, and changed starts without source execution."""

    def __init__(
        self,
        cache_root: Path,
        repository: str,
        baseline_commit: str,
        target_commit: str,
        baseline_tree: str,
        target_tree: str,
        *,
        budget: EvidenceBudget | None = None,
        runner: GitRunner | None = None,
    ) -> None:
        self.cache = cache_root / collision_resistant_cache_name(repository)
        self.repository = repository
        self.commits = {"baseline": baseline_commit, "target": target_commit}
        self.trees = {"baseline": baseline_tree, "target": target_tree}
        self.budget = budget or EvidenceBudget()
        self.runner = runner or self._run_git
        self._locations: set[tuple[object, ...]] = set()
        self._blobs: dict[str, tuple[int, int]] = {}
        self._verified = False

    def validate_edges(self, edges: Sequence[EvidenceEdge]) -> None:
        if not edges:
            raise GroundTruthError("evidence chain must not be empty")
        if [edge.ordinal for edge in edges] != list(range(len(edges))):
            raise GroundTruthError("evidence edge ordinals must be dense")
        self._verify_repository()
        for edge in edges:
            self.validate_location(edge.from_location)
            self.validate_location(edge.to_location)
        for previous, current in pairwise(edges):
            if previous.to_location != current.from_location:
                raise GroundTruthError("evidence chain is disconnected")
        if not self._location_is_changed(edges[0].from_location):
            raise GroundTruthError("evidence chain does not start in a changed line range")

    def validate_location(self, location: EvidenceLocation) -> None:
        expected_commit = self.commits[location.side]
        if location.commit_sha != expected_commit:
            raise GroundTruthError("evidence is bound to the wrong snapshot commit")
        key = (
            location.side,
            location.commit_sha,
            location.blob_sha,
            location.path,
            location.start_line,
            location.end_line,
        )
        if key in self._locations:
            return
        tree = self._git("rev-parse", f"{location.commit_sha}^{{tree}}").decode().strip()
        if tree != self.trees[location.side]:
            raise GroundTruthError("snapshot tree does not match corpus binding")
        listing = self._git("ls-tree", "-z", tree, "--", f":(literal){location.path}")
        records = [record for record in listing.split(b"\0") if record]
        if len(records) != 1:
            raise GroundTruthError("evidence path does not resolve to exactly one Git object")
        try:
            metadata, returned_path = records[0].split(b"\t", 1)
            mode, kind, oid = metadata.decode().split(" ")
        except (ValueError, UnicodeDecodeError) as exc:
            raise GroundTruthError("malformed git ls-tree output") from exc
        if (
            returned_path.decode("utf-8") != location.path
            or kind != "blob"
            or mode not in {"100644", "100755"}
        ):
            raise GroundTruthError("evidence path is not the claimed regular blob")
        if oid != location.blob_sha:
            raise GroundTruthError("evidence blob hash mismatch")
        if oid not in self._blobs:
            size_text = self._git("cat-file", "-s", oid).decode().strip()
            if not size_text.isdigit():
                raise GroundTruthError("invalid Git blob size")
            size = int(size_text)
            if size > self.budget.max_blob_bytes:
                raise GroundTruthError("one Git blob exceeds evidence byte budget")
            content = self._git("cat-file", "blob", oid)
            if len(content) != size:
                raise GroundTruthError("Git blob size changed while validating")
            lines = len(content.splitlines())
            self.budget.consume_blob(size, lines)
            self._blobs[oid] = (size, lines)
        line_count = self._blobs[oid][1]
        if location.end_line > line_count:
            raise GroundTruthError("evidence line range exceeds blob")
        self._locations.add(key)

    def _verify_repository(self) -> None:
        if self._verified:
            return
        if not self.cache.is_dir():
            raise GroundTruthError(f"offline Git cache is missing: {self.cache}")
        expected = f"https://github.com/{self.repository}.git"
        remote = self._git("config", "--get", "remote.origin.url").decode().strip()
        if remote != expected:
            raise GroundTruthError("Git cache remote does not match locked repository")
        for side, commit in self.commits.items():
            resolved = self._git("rev-parse", f"{commit}^{{commit}}").decode().strip()
            if resolved != commit:
                raise GroundTruthError(f"missing immutable {side} commit")
        self._verified = True

    def _location_is_changed(self, location: EvidenceLocation) -> bool:
        diff = self._git(
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--unified=0",
            self.commits["baseline"],
            self.commits["target"],
            "--",
            f":(literal){location.path}",
        )
        for line in diff.splitlines():
            match = _HUNK.match(line)
            if match is None:
                continue
            old_start, old_count, new_start, new_count = (
                int(match.group(1)),
                int(match.group(2) or b"1"),
                int(match.group(3)),
                int(match.group(4) or b"1"),
            )
            start, count = (
                (old_start, old_count) if location.side == "baseline" else (new_start, new_count)
            )
            if count and max(start, location.start_line) <= min(
                start + count - 1, location.end_line
            ):
                return True
        return False

    def _git(self, *args: str) -> bytes:
        self.budget.consume_command()
        output = self.runner(self.cache, args)
        self.budget.check_wall()
        if len(output) > _MAX_OUTPUT:
            raise GroundTruthError("Git command output exceeds evidence bound")
        return output

    @staticmethod
    def _run_git(cache: Path, args: Sequence[str]) -> bytes:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.devnull,
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        command = [
            "git",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.required=false",
            "--git-dir",
            str(cache),
            *args,
        ]
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            assert process.stdout is not None and process.stderr is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            buffers = {"stdout": bytearray(), "stderr": bytearray()}
            deadline = time.monotonic() + 30
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GroundTruthError("offline Git evidence command timed out")
                events = selector.select(min(remaining, 0.25))
                if not events and process.poll() is not None:
                    events = [(key, 0) for key in selector.get_map().values()]
                for key, _mask in events:
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    buffer.extend(chunk)
                    if len(buffer) > _MAX_OUTPUT:
                        raise GroundTruthError(f"Git command {key.data} exceeds evidence bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GroundTruthError("offline Git evidence command timed out")
            return_code = process.wait(timeout=remaining)
            if return_code != 0:
                raise GroundTruthError("offline Git evidence command failed")
            return bytes(buffers["stdout"])
        except (OSError, subprocess.SubprocessError) as exc:
            raise GroundTruthError("offline Git evidence command failed") from exc
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
