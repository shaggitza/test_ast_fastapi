"""Tests for the cheap exploratory training-dataset builder."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import patch

from benchmarks.real_world import build_training_dataset as builder


def completed_label(
    pr: int,
    *,
    entrypoints: list[dict[str, Any]] | None = None,
    status: str = "reviewed",
) -> dict[str, Any]:
    return {
        "repository": "owner/repo",
        "pr": pr,
        "status": status,
        "reviewer": {"kind": "agent", "name": "reviewer", "version": "v1"},
        "changed_symbols": ["app.handler"],
        "affected_entrypoints": entrypoints or [],
        "affected_tests": [],
        "contract_changes": [],
        "cross_repository_consumers": [],
        "unknowns": [],
        "orphans": [],
        "notes": "completed review",
    }


def http_entrypoint(path: str = "/items") -> dict[str, Any]:
    return {
        "id": f"HTTP GET {path}",
        "kind": "http",
        "confidence": "confirmed",
        "evidence": ["app.py:10 handler"],
    }


class _FakeResponse:
    def __init__(self, content: bytes, barrier: threading.Barrier | None = None) -> None:
        self.content = content
        self.barrier = barrier

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        if self.barrier is not None:
            self.barrier.wait()
        return self.content


class TrainingDatasetTests(unittest.TestCase):
    def test_build_examples_filters_scope_and_never_invents_negatives(self) -> None:
        corpus = [
            {
                "repository": "owner/repo",
                "number": 1,
                "title": "change handler",
                "body": "body",
                "files": [{"path": "app.py"}],
            },
            {"repository": "owner/repo", "number": 2, "files": []},
            {"repository": "owner/repo", "number": 3, "files": []},
        ]
        label = completed_label(
            1,
            entrypoints=[
                http_entrypoint(),
                {
                    "id": "Web UI /",
                    "kind": "other",
                    "confidence": "confirmed",
                    "evidence": ["ui.py:1 page"],
                },
            ],
        )
        label["unknowns"] = ["dynamic registration"]
        labels = {
            ("owner/repo", 1): label,
            ("owner/repo", 3): {
                "repository": "owner/repo",
                "pr": 3,
                "status": "not_evaluable",
                "affected_entrypoints": [],
            },
        }

        examples, missing = builder.build_examples(corpus, labels)

        self.assertEqual(missing, 2)
        self.assertEqual(len(examples), 1)
        self.assertEqual(examples[0]["id"], "owner/repo#1")
        self.assertEqual(examples[0]["target"]["affected_entrypoints"], [http_entrypoint()])
        self.assertIsNone(examples[0]["input"]["diff"])
        self.assertEqual(examples[0]["metadata"]["diff_source"], "missing")

    def test_local_diff_is_used_and_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            diff_dir = Path(temporary_name)
            diff = "diff --git a/app.py b/app.py\n+return 1\n"
            merge_commit = "A" * 40
            cache_name = builder.diff_filename("owner/repo", 7, merge_commit)
            self.assertEqual(cache_name, f"owner--repo--7--{'a' * 40}.diff")
            (diff_dir / cache_name).write_text(diff, encoding="utf-8")
            corpus = [
                {
                    "repository": "owner/repo",
                    "number": 7,
                    "mergeCommit": {"oid": merge_commit},
                    "files": [],
                }
            ]
            label = completed_label(7, status="adjudicated")
            labels = {("owner/repo", 7): label}

            examples, missing = builder.build_examples(corpus, labels, diff_dir=diff_dir)

        self.assertEqual(missing, 0)
        self.assertEqual(examples[0]["input"]["diff"], diff)
        self.assertEqual(examples[0]["metadata"]["diff_source"], "cache")
        self.assertEqual(
            examples[0]["metadata"]["diff_sha256"],
            hashlib.sha256(diff.encode()).hexdigest(),
        )

    def test_cache_path_accepts_supported_oid_lengths_and_stays_confined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            diff_dir = Path(temporary_name) / "diffs"
            for length in (40, 64):
                with self.subTest(length=length):
                    oid = "A" * length
                    path = builder._diff_cache_path(diff_dir, "owner/repo", 7, oid)
                    self.assertEqual(path.parent, diff_dir.absolute())
                    self.assertEqual(path.name, f"owner--repo--7--{'a' * length}.diff")
                    self.assertNotIn("/", path.name)
                    self.assertNotIn("\\", path.name)

    def test_v2_dual_status_preserves_terminal_and_filters_scope(self) -> None:
        corpus = [{"repository": "owner/repo", "number": 4, "files": []}]
        labels = {
            ("owner/repo", 4): {
                "repository": "owner/repo",
                "pr": 4,
                "status": "adjudicated",
                "terminal_status": "positive",
                "affected_entrypoints": [
                    {
                        "id": "HTTP GET /health",
                        "kind": "http",
                        "confidence": "confirmed",
                    },
                    {
                        "id": "CLI inspect",
                        "kind": "cli",
                        "confidence": "probable",
                    },
                ],
            }
        }

        examples, missing = builder.build_examples(corpus, labels, scope="fastapi")

        self.assertEqual(missing, 0)
        self.assertEqual(examples[0]["target"]["status"], "adjudicated")
        self.assertEqual(examples[0]["target"]["terminal_status"], "positive")
        self.assertEqual(
            examples[0]["target"]["affected_entrypoints"],
            [{"id": "HTTP GET /health", "kind": "http", "confidence": "confirmed"}],
        )
        self.assertNotIn("changed_symbols", examples[0]["target"])
        self.assertEqual(examples[0]["metadata"]["label_source_status"], "adjudicated")
        self.assertEqual(examples[0]["metadata"]["label_terminal_status"], "positive")

    def test_status_only_completed_label_is_rejected(self) -> None:
        corpus = [{"repository": "owner/repo", "number": 5, "files": []}]
        labels = {
            ("owner/repo", 5): {
                "repository": "owner/repo",
                "pr": 5,
                "status": "reviewed",
            }
        }

        with self.assertRaisesRegex(builder.DatasetError, "requires reviewer provenance"):
            builder.build_examples(corpus, labels)

    def test_endpoint_evidence_is_required_for_legacy_review(self) -> None:
        label = completed_label(
            6,
            entrypoints=[
                {
                    "id": "HTTP GET /items",
                    "kind": "http",
                    "confidence": "confirmed",
                }
            ],
        )

        with self.assertRaisesRegex(builder.DatasetError, "evidence"):
            builder.validate_completed_label(label)

    def test_duplicate_labels_are_rejected_before_status_filtering(self) -> None:
        pending = {"repository": "owner/repo", "pr": 1, "status": "pending_double_review"}
        complete = completed_label(1)
        with tempfile.TemporaryDirectory() as temporary_name:
            path = Path(temporary_name) / "labels.jsonl"
            for records in ((pending, complete), (complete, pending), (pending, pending)):
                with self.subTest(statuses=[record["status"] for record in records]):
                    path.write_text(
                        "".join(json.dumps(record) + "\n" for record in records),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(builder.DatasetError, "duplicate label"):
                        builder.load_labels(path)

    def test_label_statuses_are_explicit_and_contradictions_fail_closed(self) -> None:
        invalid = (
            {"repository": "owner/repo", "pr": 1},
            {"repository": "owner/repo", "pr": 1, "status": 1},
            {"repository": "owner/repo", "pr": 1, "status": "reviewd"},
            {
                "repository": "owner/repo",
                "pr": 1,
                "status": "adjudicated",
                "terminal_status": "postive",
            },
            {
                "repository": "owner/repo",
                "pr": 1,
                "status": "reviewed",
                "terminal_status": "positive",
            },
        )
        with tempfile.TemporaryDirectory() as temporary_name:
            path = Path(temporary_name) / "labels.jsonl"
            for label in invalid:
                with self.subTest(label=label):
                    path.write_text(json.dumps(label) + "\n", encoding="utf-8")
                    with self.assertRaises(builder.DatasetError):
                        builder.load_labels(path)

    def test_only_enumerated_skippable_shapes_are_accepted(self) -> None:
        rows = [
            {"repository": "owner/repo", "pr": 1, "status": "pending_double_review"},
            {"repository": "owner/repo", "pr": 2, "status": "unknown"},
            {
                "repository": "owner/repo",
                "pr": 3,
                "status": "not_evaluable",
                "terminal_status": "not_evaluable",
                "affected_entrypoints": [],
            },
        ]
        with tempfile.TemporaryDirectory() as temporary_name:
            path = Path(temporary_name) / "labels.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            self.assertEqual(builder.load_labels(path), {})

    def test_record_key_rejects_conflicting_aliases(self) -> None:
        with self.assertRaisesRegex(builder.DatasetError, "conflicting"):
            builder.record_key({"repository": "owner/repo", "pr": 1, "number": 999})

    def test_v2_optional_target_fields_are_validated(self) -> None:
        base: dict[str, Any] = {
            "repository": "owner/repo",
            "pr": 4,
            "status": "adjudicated",
            "terminal_status": "positive",
            "affected_entrypoints": [
                {"id": "HTTP GET /", "kind": "http", "confidence": "confirmed"}
            ],
        }
        for field in (
            "changed_symbols",
            "affected_tests",
            "contract_changes",
            "unknowns",
            "orphans",
        ):
            with self.subTest(field=field):
                label = {**base, field: "not-a-list"}
                with self.assertRaisesRegex(builder.DatasetError, field):
                    builder.validate_completed_label(label)

    def test_legacy_completed_contract_requires_cross_consumers_and_notes(self) -> None:
        label = completed_label(8)
        del label["cross_repository_consumers"]
        with self.assertRaisesRegex(builder.DatasetError, "cross_repository_consumers"):
            builder.validate_completed_label(label)
        label = completed_label(8)
        del label["notes"]
        with self.assertRaisesRegex(builder.DatasetError, "notes"):
            builder.validate_completed_label(label)

    def test_strict_json_rejects_duplicate_keys_and_non_finite_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            duplicate = root / "duplicate.jsonl"
            duplicate.write_text(
                '{"repository":"owner/repo","pr":1,"pr":2,"status":"reviewed"}\n',
                encoding="utf-8",
            )
            non_finite = root / "corpus.json"
            non_finite.write_text('{"entries":[],"value":NaN}\n', encoding="utf-8")

            with self.assertRaisesRegex(builder.DatasetError, "duplicate JSON member"):
                builder.read_jsonl(duplicate)
            with self.assertRaisesRegex(builder.DatasetError, "non-finite JSON number"):
                builder.load_corpus(non_finite)

    def test_corpus_merge_commit_rejects_malformed_present_values(self) -> None:
        malformed: tuple[object, ...] = (
            {"oid": "/../../secret"},
            {"oid": "..\\..\\secret"},
            {"oid": "." * 40},
            {"oid": "a" * 39},
            {"oid": "g" * 40},
            {"sha": "a" * 40},
            "/../../secret",
            "",
            [],
            1,
        )
        with tempfile.TemporaryDirectory() as temporary_name:
            path = Path(temporary_name) / "corpus.json"
            for merge_commit in malformed:
                with self.subTest(merge_commit=merge_commit):
                    path.write_text(
                        json.dumps(
                            {
                                "entries": [
                                    {
                                        "repository": "owner/repo",
                                        "number": 7,
                                        "mergeCommit": merge_commit,
                                    }
                                ]
                            }
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(builder.DatasetError, "mergeCommit"):
                        builder.load_corpus(path)

    def test_merge_commit_traversal_cannot_read_or_write_outside_diff_dir(self) -> None:
        labels = {("owner/repo", 7): completed_label(7)}
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            diff_dir = root / "diffs"
            diff_dir.mkdir()
            # This component made the old `...--/../../...` cache path traversable.
            (diff_dir / "owner--repo--7--").mkdir()
            outside_secret = root / "secre.diff"
            outside_secret.write_text("SECRET OUTSIDE CACHE\n", encoding="utf-8")
            outside_write = root / "writt.diff"

            for merge_commit in (
                {"oid": "/../../secret"},
                {"oid": "/../../written"},
                {"oid": "..\\..\\secret"},
                {"oid": "." * 40},
            ):
                corpus = [
                    {
                        "repository": "owner/repo",
                        "number": 7,
                        "mergeCommit": merge_commit,
                        "files": [],
                    }
                ]
                with (
                    self.subTest(merge_commit=merge_commit),
                    patch.object(builder, "_read_diff") as read_diff,
                    patch.object(builder, "urlopen") as network,
                    self.assertRaisesRegex(builder.DatasetError, "mergeCommit"),
                ):
                    builder.build_examples(
                        corpus,
                        labels,
                        diff_dir=diff_dir,
                        fetch_missing=True,
                    )
                read_diff.assert_not_called()
                network.assert_not_called()
                self.assertEqual(
                    outside_secret.read_text(encoding="utf-8"), "SECRET OUTSIDE CACHE\n"
                )
                self.assertFalse(outside_write.exists())

    def test_jsonl_serialization_rejects_non_finite_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name) / "dataset.jsonl"

            with self.assertRaisesRegex(builder.DatasetError, "strict JSON"):
                builder._write_jsonl(output, [{"value": float("nan")}])

            self.assertFalse(output.exists())

    def test_output_rejects_existing_protected_and_input_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            existing = root / "dataset.jsonl"
            existing.write_text("old\n", encoding="utf-8")
            source = root / "labels.jsonl"
            source.write_text("input\n", encoding="utf-8")

            with self.assertRaisesRegex(builder.DatasetError, "already exists"):
                builder._write_jsonl(existing, [])
            with self.assertRaisesRegex(builder.DatasetError, "overwrite input"):
                builder._write_jsonl(source, [], input_paths=(source,))
            with self.assertRaisesRegex(builder.DatasetError, "frozen benchmark"):
                builder._write_jsonl(builder.HERE / "corpus.json", [])

            self.assertEqual(existing.read_text(encoding="utf-8"), "old\n")
            self.assertEqual(source.read_text(encoding="utf-8"), "input\n")

    def test_jsonl_publication_race_has_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name) / "dataset.jsonl"
            barrier = threading.Barrier(2)

            def publish(value: int) -> str:
                barrier.wait()
                try:
                    builder._write_jsonl(output, [{"value": value}])
                except builder.DatasetError:
                    return "lost"
                return "won"

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(publish, (1, 2)))

            self.assertEqual(sorted(results), ["lost", "won"])
            self.assertIn(output.read_text(encoding="utf-8"), {'{"value": 1}\n', '{"value": 2}\n'})

    def test_download_cache_is_exclusive_and_race_safe_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            destination = Path(temporary_name) / "cache.diff"
            barrier = threading.Barrier(2)

            def fake_urlopen(_request: object, *, timeout: float) -> _FakeResponse:
                self.assertEqual(timeout, 30.0)
                return _FakeResponse(b"complete diff\n", barrier)

            def fetch() -> str:
                try:
                    builder.fetch_diff("https://github.com/owner/repo/pull/1.diff", destination)
                except builder.DatasetError:
                    return "lost"
                return "won"

            with (
                patch.object(builder, "urlopen", side_effect=fake_urlopen),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                results = list(executor.map(lambda _index: fetch(), range(2)))

            self.assertEqual(sorted(results), ["lost", "won"])
            self.assertEqual(destination.read_bytes(), b"complete diff\n")

    def test_publication_parent_swap_cannot_redirect_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            parent = root / "parent"
            held = root / "held"
            protected = root / "protected"
            parent.mkdir()
            protected.mkdir()
            output = parent / "dataset.jsonl"
            real_link = os.link

            def swap_then_link(*args: Any, **kwargs: Any) -> None:
                parent.rename(held)
                parent.symlink_to(protected, target_is_directory=True)
                real_link(*args, **kwargs)

            with patch("benchmarks.real_world._secure_publish.os.link", side_effect=swap_then_link):
                builder._write_jsonl(output, [{"stable": True}])

            self.assertTrue((held / "dataset.jsonl").is_file())
            self.assertFalse((protected / "dataset.jsonl").exists())

    def test_download_parent_swap_cannot_redirect_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            parent = root / "parent"
            held = root / "held"
            protected = root / "protected"
            parent.mkdir()
            protected.mkdir()
            destination = parent / "cache.diff"
            real_link = os.link

            def swap_then_link(*args: Any, **kwargs: Any) -> None:
                parent.rename(held)
                parent.symlink_to(protected, target_is_directory=True)
                real_link(*args, **kwargs)

            with (
                patch.object(builder, "urlopen", return_value=_FakeResponse(b"diff\n")),
                patch(
                    "benchmarks.real_world._secure_publish.os.link",
                    side_effect=swap_then_link,
                ),
            ):
                builder.fetch_diff("https://github.com/owner/repo/pull/1.diff", destination)

            self.assertEqual((held / "cache.diff").read_bytes(), b"diff\n")
            self.assertFalse((protected / "cache.diff").exists())

    def test_cache_rejects_symlinks_hardlinks_aliases_and_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            source = root / "source.diff"
            source.write_bytes(b"diff\n")
            symlink = root / "symlink.diff"
            symlink.symlink_to(source)
            with self.assertRaises(builder.DatasetError):
                builder._read_diff(symlink)

            hardlink = root / "hardlink.diff"
            os.link(source, hardlink)
            with self.assertRaisesRegex(builder.DatasetError, "exactly one hard link"):
                builder._read_diff(hardlink, input_paths=(source,))

            invalid = root / "invalid.diff"
            invalid.write_bytes(b"abc\xffdef")
            with self.assertRaisesRegex(builder.DatasetError, "valid UTF-8"):
                builder._read_diff(invalid)

    def test_invalid_download_utf8_does_not_consume_cache_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            destination = Path(temporary_name) / "cache.diff"
            with (
                patch.object(builder, "urlopen", return_value=_FakeResponse(b"abc\xffdef")),
                self.assertRaisesRegex(builder.DatasetError, "valid UTF-8"),
            ):
                builder.fetch_diff("https://github.com/owner/repo/pull/1.diff", destination)
            self.assertFalse(destination.exists())

    def test_first_fetch_and_later_cache_examples_are_byte_identical(self) -> None:
        corpus = [{"repository": "owner/repo", "number": 9, "files": []}]
        labels = {("owner/repo", 9): completed_label(9)}
        with tempfile.TemporaryDirectory() as temporary_name:
            diff_dir = Path(temporary_name) / "diffs"
            with patch.object(builder, "urlopen", return_value=_FakeResponse(b"same diff\n")):
                first, _missing = builder.build_examples(
                    corpus, labels, diff_dir=diff_dir, fetch_missing=True
                )
            second, _missing = builder.build_examples(
                corpus, labels, diff_dir=diff_dir, fetch_missing=True
            )
        first_bytes = json.dumps(first, sort_keys=True, allow_nan=False).encode()
        second_bytes = json.dumps(second, sort_keys=True, allow_nan=False).encode()
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first[0]["metadata"]["diff_source"], "cache")

    def test_existing_download_destination_fails_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            destination = Path(temporary_name) / "cache.diff"
            destination.write_bytes(b"trusted cache\n")

            with (
                patch.object(builder, "urlopen") as mocked_urlopen,
                self.assertRaisesRegex(builder.DatasetError, "already exists"),
            ):
                builder.fetch_diff("https://github.com/owner/repo/pull/1.diff", destination)

            mocked_urlopen.assert_not_called()
            self.assertEqual(destination.read_bytes(), b"trusted cache\n")


if __name__ == "__main__":
    unittest.main()
