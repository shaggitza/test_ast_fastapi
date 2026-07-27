"""Mocked, stdlib-only tests for the current-analyzer corpus runner."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from benchmarks.real_world import evaluate, run_current
from benchmarks.real_world.benchmark_schema import read_primary_artifact

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


def entry(repository: str, pr: int, *, python: bool = True) -> dict[str, object]:
    suffix = "service.py" if python else "README.md"
    return {
        "repository": repository,
        "number": pr,
        "mergeCommit": {"oid": SHA_A},
        "commits": [SHA_C],
        "files": [{"path": suffix}],
    }


class NormalizeEndpointsTests(unittest.TestCase):
    def test_explodes_normalizes_sorts_and_deduplicates_methods(self) -> None:
        report = {
            "affected_endpoints": [
                {"endpoint": {"path": "items", "methods": ["post", "GET", "post"]}},
                {"endpoint": {"path": "//items///", "methods": "get"}},
                {"endpoint": {"path": "/events", "methods": "websocket"}},
            ]
        }

        endpoints, unresolved = run_current.normalize_endpoints(report)

        self.assertEqual(
            endpoints,
            [
                {"id": "HTTP GET /items", "kind": "http", "evidence": []},
                {"id": "HTTP GET /items/", "kind": "http", "evidence": []},
                {"id": "HTTP POST /items", "kind": "http", "evidence": []},
                {"id": "WEBSOCKET /events", "kind": "event", "evidence": []},
            ],
        )
        self.assertEqual(unresolved, [])

    def test_candidates_preserve_confidence_evidence_and_strongest_duplicate(self) -> None:
        evidence = {"effect": "argument_mutation_isolated", "schema_version": 1}
        report = {
            "affected_endpoints": [],
            "candidate_endpoints": [
                {
                    "endpoint": {"path": "/items", "methods": ["GET", "POST"]},
                    "confidence": "low",
                    "effect_evidence": [evidence],
                },
                {
                    "endpoint": {"path": "/items", "methods": ["GET"]},
                    "confidence": "high",
                    "effect_evidence": [evidence],
                },
            ],
        }

        candidates, unresolved = run_current.normalize_candidate_endpoints(report)

        self.assertEqual(unresolved, [])
        self.assertEqual(
            candidates,
            [
                {
                    "id": "HTTP GET /items",
                    "kind": "http",
                    "confidence": "high",
                    "effect_evidence": [evidence],
                },
                {
                    "id": "HTTP POST /items",
                    "kind": "http",
                    "confidence": "low",
                    "effect_evidence": [evidence],
                },
            ],
        )

    def test_candidates_fall_back_to_legacy_affected_as_medium(self) -> None:
        candidates, unresolved = run_current.normalize_candidate_endpoints(
            {"affected_endpoints": [{"endpoint": {"path": "/x", "methods": ["GET"]}}]}
        )

        self.assertEqual(unresolved, [])
        self.assertEqual(candidates[0]["confidence"], "medium")


class ResolutionAndSkipTests(unittest.TestCase):
    def config(self, temporary: Path, **overrides: object) -> run_current.RunConfig:
        values: dict[str, object] = {
            "cache": temporary / "cache",
            "output": temporary / "output.jsonl",
            "manifest": temporary / "manifest.json",
            "timeout": 5.0,
            "dry_run": False,
            "allow_upstream_execution": False,
            "use_scip": False,
            "default_app_root": ".",
            "app_roots": {},
            "candidate_root": temporary,
        }
        values.update(overrides)
        return run_current.RunConfig(**values)  # type: ignore[arg-type]

    def test_non_python_pr_is_explicitly_unresolved_without_git(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            config = self.config(Path(temporary_name))
            with mock.patch.object(run_current, "ensure_cache") as ensure_cache:
                prediction, manifest = run_current.process_entry(
                    entry("owner/repo", 7, python=False), config, "candidate"
                )

        ensure_cache.assert_not_called()
        self.assertEqual(prediction["unresolved"], ["non_python_change"])
        self.assertEqual(prediction["affected_entrypoints"], [])
        self.assertNotIn("incremental_seconds", prediction)
        self.assertNotIn("index_seconds", prediction)
        self.assertEqual(prediction["schema_version"], 3)
        self.assertEqual(prediction["status"], "unresolved")
        self.assertEqual(manifest["reason"], "non_python_change")
        self.assertEqual(manifest["merge_sha"], SHA_A)

    def test_python_pr_uses_secure_analysis_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            config = self.config(temporary)

            def make_worktree(_cache: Path, worktree: Path, _base: str) -> None:
                worktree.mkdir()

            with (
                mock.patch.object(run_current, "ensure_cache", return_value=temporary / "bare"),
                mock.patch.object(run_current, "merge_parents", return_value=[SHA_B]),
                mock.patch.object(
                    run_current, "add_detached_worktree", side_effect=make_worktree
                ) as add_worktree,
                mock.patch.object(run_current, "write_local_diff"),
                mock.patch.object(run_current, "remove_worktree"),
                mock.patch.object(
                    run_current, "invoke_analyzer", return_value=([], [], [], 0.25)
                ) as invoke,
            ):
                prediction, manifest = run_current.process_entry(
                    entry("owner/repo", 8), config, "candidate"
                )

        self.assertTrue(invoke.call_args.kwargs["secure_ast"])
        self.assertEqual(add_worktree.call_args.args[2], SHA_A)
        self.assertEqual(prediction["unresolved"], [])
        self.assertEqual(manifest["status"], "completed")

    def test_scip_materializes_and_cleans_target_and_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            config = self.config(temporary, use_scip=True)

            def make_worktree(_cache: Path, worktree: Path, _sha: str) -> None:
                worktree.mkdir()

            with (
                mock.patch.object(run_current, "ensure_cache", return_value=temporary / "bare"),
                mock.patch.object(run_current, "merge_parents", return_value=[SHA_B]),
                mock.patch.object(
                    run_current, "add_detached_worktree", side_effect=make_worktree
                ) as add_worktree,
                mock.patch.object(run_current, "write_local_diff"),
                mock.patch.object(run_current, "remove_worktree") as remove_worktree,
                mock.patch.object(
                    run_current, "invoke_analyzer", return_value=([], [], [], 0.1)
                ) as invoke,
            ):
                prediction, _manifest = run_current.process_entry(
                    entry("owner/repo", 8), config, "candidate"
                )

        assert [call.args[2] for call in add_worktree.call_args_list] == [SHA_A, SHA_B]
        assert remove_worktree.call_count == 2
        assert invoke.call_args.kwargs["baseline_app_root"].name == "baseline"
        assert prediction["unresolved"] == []

    def test_scip_cleans_partially_created_baseline_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            config = self.config(temporary, use_scip=True)
            calls = 0

            def fail_baseline(_cache: Path, worktree: Path, _sha: str) -> None:
                nonlocal calls
                calls += 1
                worktree.mkdir()
                if calls == 2:
                    raise run_current.RunnerError("partial baseline failure")

            with (
                mock.patch.object(run_current, "ensure_cache", return_value=temporary / "bare"),
                mock.patch.object(run_current, "merge_parents", return_value=[SHA_B]),
                mock.patch.object(run_current, "add_detached_worktree", side_effect=fail_baseline),
                mock.patch.object(run_current, "remove_worktree") as remove_worktree,
            ):
                prediction, _manifest = run_current.process_entry(
                    entry("owner/repo", 8), config, "candidate"
                )

        assert remove_worktree.call_count == 2
        assert "partial baseline failure" in prediction["unresolved"][0]

    def test_missing_configured_root_is_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            config = self.config(
                temporary,
                allow_upstream_execution=True,
                app_roots={"owner/repo": "backend/missing"},
            )

            def make_worktree(_cache: Path, worktree: Path, _base: str) -> None:
                worktree.mkdir()

            with (
                mock.patch.object(run_current, "ensure_cache", return_value=temporary / "bare"),
                mock.patch.object(run_current, "merge_parents", return_value=[SHA_B]),
                mock.patch.object(run_current, "add_detached_worktree", side_effect=make_worktree),
                mock.patch.object(run_current, "remove_worktree"),
                mock.patch.object(run_current, "invoke_analyzer") as invoke,
            ):
                prediction, manifest = run_current.process_entry(
                    entry("owner/repo", 8), config, "candidate"
                )

        invoke.assert_not_called()
        self.assertIn("configured app root does not exist", prediction["unresolved"][0])
        self.assertEqual(manifest["base_sha"], SHA_B)

    def test_opt_in_reaches_analyzer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            config = self.config(temporary, allow_upstream_execution=True)

            def make_worktree(_cache: Path, worktree: Path, _base: str) -> None:
                worktree.mkdir()

            with (
                mock.patch.object(run_current, "ensure_cache", return_value=temporary / "bare"),
                mock.patch.object(run_current, "merge_parents", return_value=[SHA_B]),
                mock.patch.object(run_current, "add_detached_worktree", side_effect=make_worktree),
                mock.patch.object(run_current, "write_local_diff"),
                mock.patch.object(run_current, "remove_worktree"),
                mock.patch.object(
                    run_current, "invoke_analyzer", return_value=([], [], [], 0.25)
                ) as invoke,
            ):
                prediction, manifest = run_current.process_entry(
                    entry("owner/repo", 9), config, "candidate"
                )

        invoke.assert_called_once()
        self.assertFalse(invoke.call_args.kwargs["secure_ast"])
        self.assertEqual(prediction["unresolved"], [])
        self.assertEqual(prediction["schema_version"], 3)
        self.assertEqual(prediction["status"], "completed")
        self.assertEqual(prediction["timing_seconds"], {"cold_no_cache_analyzer_wall": 0.25})
        self.assertNotIn("incremental_seconds", prediction)
        self.assertNotIn("index_seconds", prediction)
        self.assertEqual(manifest["status"], "completed")

    def test_ambiguous_parent_is_unresolved(self) -> None:
        with self.assertRaisesRegex(run_current.RunnerError, "expected exactly one"):
            run_current.resolve_base_parent([SHA_A, SHA_B], [])


class AnalyzerFailureTests(unittest.TestCase):
    def test_opt_in_invokes_exact_analyzer_command(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["uv"],
            returncode=0,
            stdout=json.dumps({"affected_endpoints": [], "errors": [], "warnings": []}),
            stderr="",
        )
        with mock.patch.object(run_current, "command", return_value=completed) as command:
            run_current.invoke_analyzer(
                Path("candidate"),
                Path("app"),
                Path("p.diff"),
                2,
                secure_ast=True,
                use_scip=True,
                app_entry="main:create_app",
                bootstrap_entry="main:run",
                baseline_app_root=Path("baseline"),
            )

        command.assert_called_once_with(
            [
                "uv",
                "run",
                "--frozen",
                "fastapi-endpoint-detector",
                "analyze",
                "--app",
                "app",
                "--diff",
                "p.diff",
                "--format",
                "json",
                "--no-cache",
                "--secure-ast",
                "--app-entry",
                "main:create_app",
                "--bootstrap-entry",
                "main:run",
                "--scip",
                "--baseline-app",
                "baseline",
            ],
            cwd=Path("candidate"),
            timeout=2,
        )

    def test_subprocess_failure_is_preserved_as_unresolved(self) -> None:
        failed = subprocess.CompletedProcess(
            args=["uv"], returncode=9, stdout="", stderr="mypy exploded"
        )
        with (
            mock.patch.object(run_current, "command", return_value=failed),
            self.assertRaisesRegex(
                run_current.RunnerError,
                r"analyzer failed \(9\): stderr:\nmypy exploded",
            ),
        ):
            run_current.invoke_analyzer(
                Path("candidate"),
                Path("app"),
                Path("p.diff"),
                2,
                secure_ast=True,
                use_scip=False,
            )

    def test_subprocess_failure_preserves_both_output_streams(self) -> None:
        failed = subprocess.CompletedProcess(
            args=["uv"], returncode=1, stdout="Error: useful detail", stderr="Aborted!"
        )
        with (
            mock.patch.object(run_current, "command", return_value=failed),
            self.assertRaisesRegex(
                run_current.RunnerError,
                r"stdout:\nError: useful detail\nstderr:\nAborted!",
            ),
        ):
            run_current.invoke_analyzer(
                Path("candidate"),
                Path("app"),
                Path("p.diff"),
                2,
                secure_ast=True,
                use_scip=False,
            )

    def test_report_errors_and_warnings_are_preserved(self) -> None:
        report = {
            "affected_endpoints": [],
            "errors": ["could not map change"],
            "warnings": [{"message": "dynamic route"}],
        }
        completed = subprocess.CompletedProcess(
            args=["uv"], returncode=0, stdout=json.dumps(report), stderr=""
        )
        with mock.patch.object(run_current, "command", return_value=completed):
            _endpoints, _candidates, unresolved, _elapsed = run_current.invoke_analyzer(
                Path("candidate"),
                Path("app"),
                Path("p.diff"),
                2,
                secure_ast=True,
                use_scip=False,
            )

        self.assertEqual(
            unresolved,
            [
                "analyzer_error: could not map change",
                'analyzer_warning: {"message": "dynamic route"}',
            ],
        )


class OutputCardinalityTests(unittest.TestCase):
    def test_main_rejects_colliding_artifact_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            corpus = Path(temporary_name) / "corpus.json"
            corpus.write_text('{"entries": []}', encoding="utf-8")
            with self.assertRaises(SystemExit):
                run_current.main(
                    [
                        "--corpus",
                        str(corpus),
                        "--output",
                        str(corpus),
                        "--manifest",
                        str(Path(temporary_name) / "manifest.json"),
                    ]
                )

    def test_main_writes_one_unique_row_per_selected_pr(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            corpus = temporary / "corpus.json"
            output = temporary / "predictions.jsonl"
            manifest = temporary / "manifest.json"
            corpus.write_text(
                json.dumps(
                    {
                        "entries": [
                            entry("owner/one", 1, python=False),
                            entry("owner/two", 2, python=False),
                            entry("owner/two", 3, python=False),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            candidate = {
                "id": "candidate",
                "name": "fastapi-endpoint-detector",
                "version": "test",
                "adapter": "fastapi-adapter-v1",
                "git_sha": SHA_A,
                "config_hash": "d" * 12,
                "dirty": False,
                "dirty_sha256": None,
                "uv_lock_sha256": "b" * 64,
                "uv_version": "uv test",
                "command": "uv run --frozen fastapi-endpoint-detector analyze --no-cache",
                "performance_protocol": {
                    "id": "cold-no-cache-analyzer-wall-v1",
                    "cache_enabled": False,
                    "incremental_valid": False,
                },
            }
            with mock.patch.object(run_current, "candidate_metadata", return_value=candidate):
                result = run_current.main(
                    [
                        "--corpus",
                        str(corpus),
                        "--cache",
                        str(temporary / "cache"),
                        "--output",
                        str(output),
                        "--manifest",
                        str(manifest),
                        "--limit",
                        "2",
                    ]
                )

            output_bytes = output.read_bytes()
            rows = [json.loads(line) for line in output_bytes.decode().splitlines()]
            manifest_data = json.loads(manifest.read_text())
            prediction_artifact = read_primary_artifact(output, "prediction")
            manifest_binding = evaluate.read_prediction_manifest(manifest, prediction_artifact)

        self.assertEqual(result, 0)
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {(row["repository"], row["pr"]) for row in rows},
            {("owner/one", 1), ("owner/two", 2)},
        )
        self.assertEqual(manifest_data["selection_count"], 2)
        self.assertEqual(len(manifest_data["prs"]), 2)
        self.assertEqual(manifest_data["schema_version"], 3)
        self.assertEqual(manifest_data["prediction_schema_version"], 3)
        self.assertEqual(manifest_data["prediction_output"]["records"], 2)
        self.assertEqual(
            manifest_data["prediction_output"]["sha256"],
            hashlib.sha256(output_bytes).hexdigest(),
        )
        self.assertEqual(
            manifest_data["selected_keys"],
            [
                {"repository": "owner/one", "pr": 1},
                {"repository": "owner/two", "pr": 2},
            ],
        )
        self.assertFalse(manifest_data["timing"]["incremental_valid"])
        self.assertEqual(manifest_binding["candidate"], "candidate")
        self.assertEqual(manifest_binding["prediction_sha256"], prediction_artifact.sha256)


if __name__ == "__main__":
    unittest.main()
