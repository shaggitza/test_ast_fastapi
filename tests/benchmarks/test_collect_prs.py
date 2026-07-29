"""Offline tests for the exploratory PR metadata collector."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest.mock import patch

from benchmarks.real_world import collect_prs as collector

OID = "a" * 40


def _fake_gh(path: Path, output: bytes) -> None:
    path.write_text(
        f"#!{sys.executable}\nimport os\nos.write(1, {output!r})\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def pr_summary(number: int = 1) -> dict[str, object]:
    return {
        "number": number,
        "title": "title",
        "url": f"https://github.com/owner/repo/pull/{number}",
        "mergedAt": "2025-01-01T00:00:00Z",
        "mergeCommit": {"oid": OID},
        "baseRefName": "main",
        "headRefName": "feature",
        "author": {"id": "user", "login": "author", "name": None, "is_bot": False},
    }


def pr_detail() -> dict[str, object]:
    return {
        "additions": 1,
        "deletions": 0,
        "changedFiles": 1,
        "files": [{"path": "app.py", "additions": 1, "deletions": 0, "changeType": "MODIFIED"}],
        "body": "body",
        "commits": [{"oid": OID}],
    }


class CollectorTests(unittest.TestCase):
    def test_config_requires_positive_limit_and_nonempty_repository_objects(self) -> None:
        invalid_configs = (
            {"prs_per_repository": 0, "repositories": [{"name": "owner/repo"}]},
            {"prs_per_repository": True, "repositories": [{"name": "owner/repo"}]},
            {"prs_per_repository": 1, "repositories": []},
            {"prs_per_repository": 1, "repositories": ["owner/repo"]},
            {"prs_per_repository": 1, "repositories": [{"name": "  "}]},
        )
        with tempfile.TemporaryDirectory() as temporary_name:
            path = Path(temporary_name) / "config.json"
            for config in invalid_configs:
                with self.subTest(config=config):
                    path.write_text(json.dumps(config), encoding="utf-8")
                    with self.assertRaises(collector.CollectorError):
                        collector._resolve_config(path, None, None)

    def test_cli_config_error_is_controlled_and_never_collects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            config = root / "config.json"
            output = root / "output.json"
            config.write_text(
                json.dumps({"prs_per_repository": -1, "repositories": []}), encoding="utf-8"
            )

            with (
                patch.object(collector, "collect_repository") as collect,
                self.assertRaises(SystemExit) as raised,
            ):
                collector.main(["--config", str(config), "--output", str(output)])

            self.assertEqual(raised.exception.code, 2)
            collect.assert_not_called()
            self.assertFalse(output.exists())

    def test_invalid_config_utf8_is_a_controlled_cli_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            config = root / "config.json"
            output = root / "output.json"
            config.write_bytes(b'{"repositories": ["\xff"]}')
            stderr = io.StringIO()

            with (
                redirect_stderr(stderr),
                patch.object(collector, "collect_repository") as collect,
                self.assertRaises(SystemExit) as raised,
            ):
                collector.main(["--config", str(config), "--output", str(output)])

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("cannot read config", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            collect.assert_not_called()
            self.assertFalse(output.exists())

    def test_cli_overrides_are_validated_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            config = root / "config.json"
            output = root / "output.json"
            config.write_text(
                json.dumps({"prs_per_repository": 20, "repositories": [{"name": "owner/repo"}]}),
                encoding="utf-8",
            )

            with (
                patch.object(collector, "collect_repository") as collect,
                self.assertRaises(SystemExit) as raised,
            ):
                collector.main(
                    [
                        "--config",
                        str(config),
                        "--repository",
                        "",
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(raised.exception.code, 2)
            collect.assert_not_called()

    def test_strict_json_rejects_duplicate_keys_and_non_finite_values(self) -> None:
        with self.assertRaisesRegex(collector.CollectorError, "duplicate JSON key"):
            collector._strict_json_loads('{"limit":1,"limit":2}', "config")
        with self.assertRaisesRegex(collector.CollectorError, "non-finite JSON number"):
            collector._strict_json_loads('{"limit":Infinity}', "config")

    def test_gh_subprocess_decodes_utf8_independently_of_ascii_locale(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            _fake_gh(root / "gh", '{"title":"café"}\n'.encode())
            environment = {
                "PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}",
                "LC_ALL": "C",
                "LANG": "C",
                "PYTHONUTF8": "0",
                "PYTHONCOERCECLOCALE": "0",
            }
            with patch.dict(os.environ, environment):
                self.assertEqual(collector.gh_json("api", "test"), {"title": "café"})

    def test_invalid_gh_utf8_is_collector_error_and_controlled_cli_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            config = root / "config.json"
            output = root / "output.json"
            config.write_text(
                json.dumps({"prs_per_repository": 1, "repositories": [{"name": "owner/repo"}]}),
                encoding="utf-8",
            )
            _fake_gh(root / "gh", b'{"title":"\xff"}\n')
            environment = {
                "PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}",
                "LC_ALL": "C",
                "LANG": "C",
                "PYTHONUTF8": "0",
                "PYTHONCOERCECLOCALE": "0",
            }
            with (
                patch.dict(os.environ, environment),
                self.assertRaisesRegex(collector.CollectorError, "not valid UTF-8") as raised,
            ):
                collector.gh_json("api", "test")
            self.assertIsInstance(raised.exception.__cause__, UnicodeDecodeError)

            stderr = io.StringIO()
            with (
                patch.dict(os.environ, environment),
                redirect_stderr(stderr),
                self.assertRaises(SystemExit) as exited,
            ):
                collector.main(["--config", str(config), "--output", str(output)])
            self.assertEqual(exited.exception.code, 2)
            self.assertIn("gh response is not valid UTF-8", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertFalse(output.exists())

    def test_publication_rejects_existing_protected_and_input_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            existing = root / "candidate.json"
            existing.write_text("old\n", encoding="utf-8")
            config = root / "config.json"
            config.write_text("input\n", encoding="utf-8")

            with self.assertRaisesRegex(collector.CollectorError, "already exists"):
                collector._publish_output(existing, {"entries": []})
            with self.assertRaisesRegex(collector.CollectorError, "overwrite input"):
                collector._publish_output(config, {"entries": []}, input_paths=(config,))
            with self.assertRaisesRegex(collector.CollectorError, "frozen benchmark"):
                collector._publish_output(collector.HERE / "corpus.json", {"entries": []})

            self.assertEqual(existing.read_text(encoding="utf-8"), "old\n")
            self.assertEqual(config.read_text(encoding="utf-8"), "input\n")

    def test_serialization_rejects_non_finite_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name) / "candidate.json"

            with self.assertRaisesRegex(collector.CollectorError, "strict JSON"):
                collector._publish_output(output, {"value": float("nan")})

            self.assertFalse(output.exists())

    def test_collect_repository_validates_all_consumed_gh_fields(self) -> None:
        malformed_responses = (
            ([{**pr_summary(), "number": True}],),
            ([pr_summary(), pr_summary()],),
            ([{**pr_summary(), "mergeCommit": {"oid": "bad"}}],),
            ([pr_summary()], {**pr_detail(), "additions": -1}),
            ([pr_summary()], {**pr_detail(), "changedFiles": "1"}),
            ([pr_summary()], {**pr_detail(), "files": "app.py"}),
            (
                [pr_summary()],
                {
                    **pr_detail(),
                    "files": [
                        {
                            "path": "",
                            "additions": 1,
                            "deletions": 0,
                            "changeType": "MODIFIED",
                        }
                    ],
                },
            ),
            ([pr_summary()], {**pr_detail(), "commits": [{"oid": "bad"}]}),
            ([{**pr_summary(), "author": "author"}],),
        )
        for responses in malformed_responses:
            with (
                self.subTest(responses=responses),
                patch.object(collector, "gh_json", side_effect=responses),
                self.assertRaises(collector.CollectorError),
            ):
                collector.collect_repository("owner/repo", 20)

    def test_collect_repository_accepts_valid_offline_responses(self) -> None:
        with patch.object(collector, "gh_json", side_effect=([pr_summary()], pr_detail())):
            entries = collector.collect_repository("owner/repo", 20)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["number"], 1)
        collector._validate_output_payload({"entries": entries})

    def test_main_revalidates_assembled_payload_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            config = root / "config.json"
            output = root / "output.json"
            config.write_text(
                json.dumps({"prs_per_repository": 1, "repositories": [{"name": "owner/repo"}]}),
                encoding="utf-8",
            )
            malformed = [{"repository": "owner/repo", "number": True}]
            with (
                patch.object(collector, "collect_repository", return_value=malformed),
                self.assertRaises(SystemExit) as raised,
            ):
                collector.main(["--config", str(config), "--output", str(output)])
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(output.exists())

    def test_publication_parent_swap_cannot_redirect_collector_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            parent = root / "parent"
            held = root / "held"
            protected = root / "protected"
            parent.mkdir()
            protected.mkdir()
            output = parent / "candidate.json"
            real_link = os.link

            def swap_then_link(*args: Any, **kwargs: Any) -> None:
                parent.rename(held)
                parent.symlink_to(protected, target_is_directory=True)
                real_link(*args, **kwargs)

            with patch("benchmarks.real_world._secure_publish.os.link", side_effect=swap_then_link):
                collector._publish_output(output, {"value": 1})

            self.assertEqual(json.loads((held / "candidate.json").read_text())["value"], 1)
            self.assertFalse((protected / "candidate.json").exists())

    def test_symlinked_parent_component_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            real_parent = root / "real"
            real_parent.mkdir()
            alias = root / "alias"
            alias.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(collector.CollectorError):
                collector._publish_output(alias / "candidate.json", {"value": 1})
            self.assertFalse((real_parent / "candidate.json").exists())

    def test_collector_publication_race_has_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name) / "candidate.json"
            barrier = threading.Barrier(2)

            def publish(value: int) -> str:
                barrier.wait()
                try:
                    collector._publish_output(output, {"value": value})
                except collector.CollectorError:
                    return "lost"
                return "won"

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(publish, (1, 2)))

            self.assertEqual(sorted(results), ["lost", "won"])
            self.assertIn(
                json.loads(output.read_text(encoding="utf-8"))["value"],
                {1, 2},
            )


if __name__ == "__main__":
    unittest.main()
