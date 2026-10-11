from __future__ import annotations

import base64
import copy
import io
import json
import time
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from shutil import copyfile
from unittest.mock import patch

from benchmarks.real_world import expansion_source_evidence as evidence

ROOT = Path(__file__).resolve().parents[2]
EXPANSION = ROOT / "benchmarks/real_world/expansion"
LOCK = EXPANSION / "pr-lock-100-v1.json"
CHECKSUMS = EXPANSION / "checksums-v1.json"


def response(value: object) -> bytes:
    return json.dumps(value).encode()


class SourceEvidenceTests(unittest.TestCase):
    def test_each_supported_fact_kind_has_a_strict_nested_contract(self) -> None:
        facts = {
            "python_versions": [
                {
                    "kind": "literal",
                    "path": ".python-version",
                    "value": "3.10",
                    "rule_id": "python-version-literal-v1",
                },
                {
                    "kind": "requires-python",
                    "path": "pyproject.toml",
                    "expression": ">=3.10",
                    "rule_id": "pyproject-requires-python-v1",
                },
                {
                    "kind": "python_requires",
                    "path": "setup.cfg",
                    "expression": ">=3.10",
                    "rule_id": "setup-cfg-python-requires-v1",
                },
                {
                    "kind": "tox-envlist",
                    "path": "tox.ini",
                    "values": ["3.10"],
                    "rule_id": "tox-envlist-python-factors-v1",
                },
            ],
            "license": [
                {
                    "kind": "spdx_identifier_expression",
                    "path": "LICENSE",
                    "expression": "MIT",
                    "rule_id": "spdx-line-v1",
                },
                {
                    "kind": "license_file_present",
                    "path": "LICENSE",
                    "rule_id": "license-presence-v1",
                },
            ],
            "dependencies": [
                {
                    "kind": "declared_dependency",
                    "path": "requirements.txt",
                    "name": "httpx",
                    "specifier": ">=1",
                    "rule_id": "requirements-static-line-v1",
                },
                {
                    "kind": "declaration_file_present",
                    "path": "setup.py",
                    "form": "dynamic_or_unsupported",
                    "rule_id": "setup-py-inert-presence-v1",
                },
            ],
        }
        for group, supported in facts.items():
            for fact in supported:
                with self.subTest(group=group, kind=fact["kind"]):
                    evidence._validate_fact(group, fact)
                    for mutation in (
                        {**fact, "unexpected": {"nested": [True, None, 1]}},
                        {**fact, "path": {"bad": True}},
                        {**fact, "path": "../unsafe"},
                        {**fact, "rule_id": []},
                        {key: value for key, value in fact.items() if key != "path"},
                    ):
                        with self.assertRaises(evidence.EvidenceError):
                            evidence._validate_fact(group, mutation)
                    if fact["kind"] == "spdx_identifier_expression":
                        with self.assertRaises(evidence.EvidenceError):
                            evidence._validate_fact(
                                group, {**fact, "expression": {"unexpected": [True]}}
                            )
                    if fact["kind"] == "declaration_file_present":
                        with self.assertRaises(evidence.EvidenceError):
                            evidence._validate_fact(group, {**fact, "form": []})

    def test_serialized_report_rejects_bad_status_and_boolean_integer(self) -> None:
        tree_sha = "1" * 40
        report = evidence.run(
            LOCK,
            CHECKSUMS,
            Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "report.json",
            responder=lambda _: response({"sha": tree_sha, "tree": [], "truncated": False}),
        )
        lock, lock_hash = evidence.frozen.load_lock(
            LOCK,
            EXPANSION / "projects-50-v1.json",
            EXPANSION / "longlist-60-v1.json",
            CHECKSUMS,
        )
        for key, value in (("status", []), ("candidate_count", True)):
            malformed = copy.deepcopy(report)
            malformed["records"][0]["base"]["license"][key] = value
            with self.subTest(key=key):
                with self.assertRaises(evidence.EvidenceError):
                    evidence._validate_serialized_report(malformed)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_report(malformed, lock, report["lock_sha256"])

        malformed = copy.deepcopy(report)
        malformed["records"][0]["base"]["license"]["facts"] = [
            {"kind": "unexpected", "path": "LICENSE", "nested": [True, None, 1]}
        ]
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(malformed, lock, report["lock_sha256"])

        invalid_facts = (
            {
                "kind": "spdx_identifier_expression",
                "path": "LICENSE",
                "expression": {"bad": []},
                "rule_id": "spdx-line-v1",
            },
            {
                "kind": "license_file_present",
                "path": "../LICENSE",
                "rule_id": "license-presence-v1",
            },
            {"kind": "license_file_present", "path": "LICENSE", "rule_id": []},
        )
        for fact in invalid_facts:
            malformed = copy.deepcopy(report)
            malformed["records"][0]["base"]["license"]["facts"] = [fact]
            with self.subTest(fact=fact), self.assertRaises(evidence.EvidenceError):
                evidence._validate_serialized_report(malformed)
            with self.subTest(fact=fact), self.assertRaises(evidence.EvidenceError):
                evidence.validate_report(malformed, lock, report["lock_sha256"])

        changed_lock_hash = copy.deepcopy(report)
        changed_lock_hash["lock_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(evidence.EvidenceError, "report_provenance_mismatch"):
            evidence.validate_report(changed_lock_hash, lock, lock_hash)
        publication_target = (
            Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "bad.json"
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "report_provenance_mismatch"):
            evidence._publish(publication_target, changed_lock_hash, lock, lock_hash)
        self.assertFalse(publication_target.exists())

    def test_synthetic_run_preserves_all_100_frozen_identities(self) -> None:
        tree_sha = "1" * 40
        calls = 0

        def responder(url: str) -> bytes:
            nonlocal calls
            calls += 1
            self.assertTrue(url.startswith("https://api.github.com/repos/"))
            return response({"sha": tree_sha, "tree": [], "truncated": False})

        output = self.enterContext(__import__("tempfile").TemporaryDirectory())
        output_path = Path(output) / "report.json"
        report = evidence.run(LOCK, CHECKSUMS, output_path, responder=responder)
        self.assertEqual(len(report["records"]), 100)
        self.assertEqual(report["network_budget"]["tree_requests"], 200)
        self.assertEqual(calls, 200)
        self.assertTrue(
            all(row["base"]["license"]["status"] == "missing" for row in report["records"])
        )
        self.assertEqual(json.loads(output_path.read_text()), report)
        self.assertEqual(
            report["lock_sha256"],
            "sha256:6df3dc426888e0c8a97a079dbac8ca48ee421fa8ecd1ce63ddd7bf825a61291f",
        )

    def test_budget_counts_attempts_and_enforces_fixed_partition(self) -> None:
        budget = evidence.Budget(time.monotonic())
        for _ in range(evidence.TREE_REQUESTS):
            budget.reserve("tree")
        with self.assertRaisesRegex(evidence.EvidenceError, "tree_request_budget_exhausted"):
            budget.reserve("tree")
        self.assertEqual((budget.requests, budget.tree_requests), (200, 200))
        for _ in range(evidence.BLOB_REQUESTS):
            budget.reserve("blob")
        for _ in range(evidence.OVERHEAD_REQUESTS):
            budget.reserve("overhead")
        with self.assertRaisesRegex(evidence.EvidenceError, "request_budget_exhausted"):
            budget.reserve("overhead")
        self.assertEqual(budget.requests, 1500)

    def test_candidate_selection_is_deduplicated_stable_and_counts_omissions(self) -> None:
        groups = {
            "python_versions": ["pyproject.toml", "pkg/tox.ini"],
            "license": ["LICENSE", "pkg/COPYING"],
            "dependencies": [
                "pyproject.toml",
                "requirements.txt",
                "uv.lock",
                "pkg/requirements-dev.txt",
            ],
        }
        chosen, omitted = evidence._select_candidates(groups)
        self.assertEqual(len(chosen), len(set(chosen)))
        self.assertEqual(chosen[:2], ["pyproject.toml", "LICENSE"])
        self.assertEqual(omitted, {"python_versions": 1, "license": 0, "dependencies": 0})

    def test_complete_tree_finds_candidate_after_entry_100(self) -> None:
        sha = "2" * 40
        entries = [
            {"path": f"file-{i:03}.txt", "type": "blob", "sha": sha, "size": 1} for i in range(130)
        ]
        entries[-1]["path"] = "LICENSE"
        budget = evidence.Budget(time.monotonic())
        api = evidence.GitHubTransport(
            None, budget, lambda _url: response({"sha": sha, "tree": entries, "truncated": False})
        )
        found, complete, errors = evidence._enumerate_tree("owner/repo", "a" * 40, api)
        self.assertTrue(complete)
        self.assertFalse(errors)
        self.assertEqual(len(found), 130)
        self.assertTrue(any(item["path"] == "LICENSE" for item in found))

    def test_truncated_tree_walks_nested_tree(self) -> None:
        root_sha, child_sha = "3" * 40, "4" * 40

        def responder(url: str) -> bytes:
            if "?recursive=1" in url:
                return response(
                    {
                        "sha": root_sha,
                        "truncated": True,
                        "tree": [{"path": "pkg", "type": "tree", "sha": child_sha}],
                    }
                )
            if url.endswith(f"/trees/{root_sha}"):
                return response(
                    {
                        "sha": root_sha,
                        "tree": [{"path": "pkg", "type": "tree", "sha": child_sha}],
                        "truncated": False,
                    }
                )
            return response(
                {
                    "sha": child_sha,
                    "tree": [{"path": "LICENSE", "type": "blob", "sha": "5" * 40, "size": 4}],
                    "truncated": False,
                }
            )

        api = evidence.GitHubTransport(None, evidence.Budget(time.monotonic()), responder)
        entries, complete, _ = evidence._enumerate_tree("owner/repo", "a" * 40, api)
        self.assertTrue(complete)
        self.assertEqual(
            entries, [{"path": "pkg/LICENSE", "sha": "5" * 40, "size": 4, "type": "blob"}]
        )

    def test_fallback_tree_requires_exact_boolean_completeness_flag(self) -> None:
        root_sha, child_sha = "3" * 40, "4" * 40
        partial_license = {"path": "LICENSE", "type": "blob", "sha": "5" * 40, "size": 4}
        for absent, malformed in ((True, None), (False, None), (False, 1), (False, "false")):
            with self.subTest(malformed=malformed, absent=absent):

                def responder(
                    url: str, absent: bool = absent, malformed: object = malformed
                ) -> bytes:
                    if "?recursive=1" in url:
                        return response({"sha": root_sha, "truncated": True, "tree": []})
                    if url.endswith(f"/trees/{root_sha}"):
                        root = {
                            "sha": root_sha,
                            "tree": [{"path": "pkg", "type": "tree", "sha": child_sha}],
                            "truncated": False,
                        }
                        return response(root)
                    page = {"sha": child_sha, "tree": [] if absent else [partial_license]}
                    if not absent:
                        page["truncated"] = malformed
                    return response(page)

                api = evidence.GitHubTransport(None, evidence.Budget(time.monotonic()), responder)
                entries, complete, errors = evidence._enumerate_tree("owner/repo", "a" * 40, api)
                self.assertFalse(complete)
                self.assertIn("tree_truncation_flag_invalid", errors)
                self.assertFalse(any(item["path"].endswith("LICENSE") for item in entries))
                license_result = evidence._group_result(
                    "license", [], set(), 0, complete, {}, root_sha, errors, {}
                )
                self.assertEqual(license_result["status"], "uncertain")

    def test_recursive_tree_requires_exact_boolean_completeness_flag(self) -> None:
        for flag in (None, 1, "false"):
            with self.subTest(flag=flag):
                api = evidence.GitHubTransport(
                    None,
                    evidence.Budget(time.monotonic()),
                    lambda _url, flag=flag: response(
                        {"sha": "3" * 40, "tree": [], "truncated": flag}
                    ),
                )
                entries, complete, errors = evidence._enumerate_tree("owner/repo", "a" * 40, api)
                self.assertFalse(complete)
                self.assertEqual(entries, [])
                self.assertEqual(errors, ["tree_truncation_flag_invalid"])

    def test_oversized_recursive_tree_falls_back_to_verified_commit_tree(self) -> None:
        tree_sha = "c" * 40

        def responder(url: str) -> bytes:
            if "?recursive=1" in url:
                return b" " * (evidence.MAX_RESPONSE_BYTES + 1)
            if "/commits/" in url:
                return response({"sha": "a" * 40, "commit": {"tree": {"sha": tree_sha}}})
            return response({"sha": tree_sha, "tree": [], "truncated": False})

        budget = evidence.Budget(time.monotonic())
        api = evidence.GitHubTransport(None, budget, responder)
        entries, complete, errors = evidence._enumerate_tree("owner/repo", "a" * 40, api)
        self.assertTrue(complete)
        self.assertEqual(entries, [])
        self.assertFalse(errors)
        self.assertEqual((budget.tree_requests, budget.overhead_requests), (1, 2))

    def test_repeated_tree_sha_marks_inventory_incomplete(self) -> None:
        root_sha, child_sha = "7" * 40, "8" * 40

        def responder(url: str) -> bytes:
            if "?recursive=1" in url:
                return response({"sha": root_sha, "truncated": True, "tree": []})
            if url.endswith(f"/trees/{root_sha}"):
                return response(
                    {
                        "sha": root_sha,
                        "tree": [
                            {"path": "again", "type": "tree", "sha": root_sha},
                            {"path": "pkg", "type": "tree", "sha": child_sha},
                        ],
                        "truncated": False,
                    }
                )
            return response({"sha": child_sha, "tree": [], "truncated": False})

        api = evidence.GitHubTransport(None, evidence.Budget(time.monotonic()), responder)
        _, complete, errors = evidence._enumerate_tree("owner/repo", "a" * 40, api)
        self.assertFalse(complete)
        self.assertIn("tree_repeated_sha", errors)

    def test_tree_page_limit_returns_incomplete_inventory(self) -> None:
        root_sha = "a" * 40
        children = [
            {"path": f"sub-{index}", "type": "tree", "sha": f"{index + 1:040x}"}
            for index in range(evidence.MAX_TREE_PAGES_PER_SIDE + 2)
        ]

        def responder(url: str) -> bytes:
            if "?recursive=1" in url:
                return response({"sha": root_sha, "truncated": True, "tree": []})
            if url.endswith(f"/trees/{root_sha}"):
                return response({"sha": root_sha, "tree": children, "truncated": False})
            tree_sha = url.rsplit("/", 1)[-1]
            return response({"sha": tree_sha, "tree": [], "truncated": False})

        budget = evidence.Budget(time.monotonic())
        api = evidence.GitHubTransport(None, budget, responder)
        _, complete, errors = evidence._enumerate_tree("owner/repo", "b" * 40, api)
        self.assertFalse(complete)
        self.assertIn("tree_page_limit", errors)
        self.assertEqual(budget.overhead_requests, evidence.MAX_TREE_PAGES_PER_SIDE)

    def test_blob_sha_is_recomputed_from_decoded_bytes(self) -> None:
        raw = b"license text\n"
        sha = evidence._git_blob_sha(raw)
        entry = {"sha": sha, "size": len(raw)}
        api = evidence.GitHubTransport(
            None,
            evidence.Budget(time.monotonic()),
            lambda _url: response(
                {
                    "sha": sha,
                    "size": len(raw),
                    "encoding": "base64",
                    "content": base64.b64encode(raw).decode(),
                }
            ),
        )
        self.assertEqual(evidence._fetch_blob("owner/repo", entry, api), raw)
        bad_api = evidence.GitHubTransport(
            None,
            evidence.Budget(time.monotonic()),
            lambda _url: response(
                {
                    "sha": sha,
                    "size": len(raw),
                    "encoding": "base64",
                    "content": base64.b64encode(b"forged").decode(),
                }
            ),
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "blob_identity_mismatch"):
            evidence._fetch_blob("owner/repo", entry, bad_api)

        forged = evidence.GitHubTransport(
            None,
            evidence.Budget(time.monotonic()),
            lambda _url: response(
                {
                    "sha": "f" * 40,
                    "size": len(raw),
                    "encoding": "base64",
                    "content": base64.b64encode(raw).decode(),
                }
            ),
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "blob_reference_mismatch"):
            evidence._fetch_blob("owner/repo", entry, forged)

    def test_http_payload_size_mismatch_fails_closed(self) -> None:
        raw = b"x"
        sha = evidence._git_blob_sha(raw)
        api = evidence.GitHubTransport(
            None,
            evidence.Budget(time.monotonic()),
            lambda _url: response(
                {
                    "sha": sha,
                    "size": 2,
                    "encoding": "base64",
                    "content": base64.b64encode(raw).decode(),
                }
            ),
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "blob_size_mismatch"):
            evidence._fetch_blob("owner/repo", {"sha": sha, "size": 1}, api)

    def test_finite_local_http_statuses_keep_collection_uncertain(self) -> None:
        sha = "1" * 40
        body = b"redirect body is accounted"

        def http_error(status: int) -> urllib.error.HTTPError:
            return urllib.error.HTTPError(
                "https://api.github.com/fixed-route",
                status,
                "fixed synthetic status",
                {},
                io.BytesIO(body),
            )

        for status in (301, 404, 410):
            budget = evidence.Budget(started=time.monotonic(), attempts=[])

            def unavailable(_url: str, code: int = status) -> bytes:
                raise http_error(code)

            api = evidence.GitHubTransport(None, budget, unavailable)
            side = evidence.collect_side("owner/repo", sha, api)
            expected = f"source_unavailable_http_{status}"
            for group in side.values():
                self.assertEqual(group["status"], "uncertain")
                self.assertIsNone(group["candidate_count"])
                self.assertIsNone(group["unknown_count"])
                self.assertIn(expected, group["reason_codes"])
                self.assertIn("tree_incomplete", group["reason_codes"])
                self.assertEqual(group["facts"], [])
            self.assertEqual(budget.requests, 1)
            self.assertEqual(budget.response_bytes, len(body))
            self.assertEqual(budget.attempts[0]["response_status"], status)
            self.assertEqual(budget.attempts[0]["response_bytes"], len(body))

        for status in (401, 403):
            budget = evidence.Budget(started=time.monotonic(), attempts=[])

            def unauthorized(_url: str, code: int = status) -> bytes:
                raise http_error(code)

            api = evidence.GitHubTransport(None, budget, unauthorized)
            with self.assertRaisesRegex(evidence.EvidenceError, f"github_http_{status}"):
                api.get_json(f"/repos/owner/repo/git/trees/{sha}?recursive=1", "tree")
            self.assertEqual(budget.requests, 1)
            self.assertEqual(budget.response_bytes, len(body))
            self.assertEqual(budget.attempts[0]["response_status"], status)

        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        for status in (401, 403):
            target = directory / f"auth-{status}.json"

            def rejected(url: str, code: int = status) -> bytes:
                raise http_error(code)

            with self.assertRaisesRegex(evidence.EvidenceError, f"github_http_{status}"):
                evidence.run(LOCK, CHECKSUMS, target, responder=rejected)
            receipt = json.loads(target.with_name(target.name + ".attempts.json").read_text())
            self.assertEqual(receipt["error_code"], f"github_http_{status}")
            self.assertEqual(receipt["counters"]["requests"], 1)
            self.assertEqual(receipt["counters"]["response_bytes"], len(body))
            self.assertEqual(receipt["attempts"][0]["response_status"], status)
            receipt_text = target.with_name(target.name + ".attempts.json").read_text()
            self.assertNotIn("fixed-route", receipt_text)
            self.assertNotIn("fixed synthetic status", receipt_text)
            self.assertNotIn(body.decode(), receipt_text)
            self.assertFalse(target.exists())

    def test_selected_blob_unavailable_is_not_missing_or_unsupported(self) -> None:
        raw = b"requires-python = '>=3.10'\n"
        blob_sha = evidence._git_blob_sha(raw)
        commit = "2" * 40
        tree = {
            "sha": commit,
            "tree": [{"path": "pyproject.toml", "type": "blob", "sha": blob_sha, "size": len(raw)}],
            "truncated": False,
        }

        def responder(url: str) -> bytes:
            if "/trees/" in url:
                return response(tree)
            raise urllib.error.HTTPError(url, 404, "not found", {}, io.BytesIO(b"blob unavailable"))

        budget = evidence.Budget(started=time.monotonic(), attempts=[])
        api = evidence.GitHubTransport(None, budget, responder)
        side = evidence.collect_side("owner/repo", commit, api)
        for name in ("python_versions", "dependencies"):
            group = side[name]
            self.assertEqual(group["status"], "uncertain")
            self.assertIn("source_unavailable_http_404", group["reason_codes"])
            self.assertIsNone(group["unknown_count"])
            self.assertEqual(group["facts"], [])
        self.assertEqual(side["license"]["status"], "missing")
        self.assertEqual(budget.requests, 2)
        self.assertEqual(budget.attempts[1]["response_status"], 404)

    def test_one_unavailable_tree_keeps_every_locked_record_uncertain(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "facts.json"

        def unavailable(url: str) -> bytes:
            raise urllib.error.HTTPError(url, 410, "gone", {}, io.BytesIO(b"gone"))

        report = evidence.run(LOCK, CHECKSUMS, target, responder=unavailable)
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["id"], "gh103-v2-source-evidence")
        self.assertEqual(len(report["records"]), 100)
        self.assertEqual(report["network_budget"]["requests"], 200)
        for record in report["records"]:
            for side in ("base", "head"):
                for group in ("python_versions", "license", "dependencies"):
                    result = record[side][group]
                    self.assertEqual(result["status"], "uncertain")
                    self.assertIsNone(result["candidate_count"])
                    self.assertIsNone(result["omitted_candidate_count"])
                    self.assertIsNone(result["unknown_count"])
                    self.assertEqual(result["declarations_present"], None)
                    self.assertEqual(result["facts"], [])
                    self.assertIn("source_unavailable_http_410", result["reason_codes"])

    def test_python_declaration_and_setup_py_are_inert_source_facts(self) -> None:
        facts = evidence._parse_python("pyproject.toml", '[project]\nrequires-python = ">=3.10"\n')
        self.assertEqual(facts[0]["expression"], ">=3.10")
        dependencies = evidence._parse_dependencies(
            "setup.py", "raise RuntimeError('must not run')"
        )
        self.assertEqual(dependencies[0]["form"], "dynamic_or_unsupported")
        with self.assertRaises(ValueError):
            evidence._parse_python(
                "pyproject.toml", '[project]\nrequires-python = ">=3.10"\n[project]\n'
            )
        tox_facts = evidence._parse_python("tox.ini", "[tox]\nenvlist = py310,py311-django\n")
        self.assertEqual(tox_facts[0]["values"], ["3.10", "3.11"])
        with self.assertRaises(NotImplementedError):
            evidence._parse_python("tox.ini", "[tox]\nenvlist = {py310,py311}\n")

    def test_mixed_supported_and_unsupported_sources_retain_unknown_count(self) -> None:
        paths = ["requirements.txt", "constraints.txt"]
        entries = [{"sha": "a" * 40, "size": 5}, {"sha": "b" * 40, "size": 8}]
        contents = {
            "requirements.txt": (entries[0], b"one\n"),
            "constraints.txt": (entries[1], b"bad line !\n"),
        }
        result = evidence._group_result(
            "dependencies", paths, set(paths), 0, True, contents, "c" * 40, [], {}
        )
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["unknown_count"], 1)
        self.assertIs(result["declarations_present"], True)

    def test_requirements_directives_are_unsupported_not_empty(self) -> None:
        content = b"-r private-requirements.txt\n"
        result = evidence._group_result(
            "dependencies",
            ["requirements.txt"],
            {"requirements.txt"},
            0,
            True,
            {"requirements.txt": ({"sha": "a" * 40, "size": len(content)}, content)},
            "c" * 40,
            [],
            {},
        )
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["unknown_count"], 1)
        self.assertIsNone(result["declarations_present"])

    def test_two_license_files_are_multiple_evidence(self) -> None:
        paths = ["LICENSE", "NOTICE"]
        content = b"SPDX-License-Identifier: MIT\n"
        refs = {
            path: ({"sha": evidence._git_blob_sha(content), "size": len(content)}, content)
            for path in paths
        }
        result = evidence._group_result(
            "license", paths, set(paths), 0, True, refs, "c" * 40, [], {}
        )
        self.assertEqual(result["status"], "multiple_or_conflicting")
        self.assertIn("multiple_evidence_items", result["reason_codes"])

    def test_malformed_spdx_expression_is_uncertain(self) -> None:
        text = b"SPDX-License-Identifier: MIT OR\n"
        ref = {"sha": evidence._git_blob_sha(text), "size": len(text)}
        result = evidence._group_result(
            "license", ["LICENSE"], {"LICENSE"}, 0, True, {"LICENSE": (ref, text)}, "d" * 40, [], {}
        )
        self.assertEqual(result["status"], "uncertain")
        self.assertIn("parse_error", result["reason_codes"])

    def test_transport_exception_does_not_expose_configured_secret(self) -> None:
        secret = "test-token-that-must-not-leak"

        def fail(_url: str) -> bytes:
            raise RuntimeError(secret)

        api = evidence.GitHubTransport(secret, evidence.Budget(time.monotonic()), fail)
        with self.assertRaises(evidence.EvidenceError) as raised:
            api.get_json("/repos/owner/repo/git/trees/" + "a" * 40, "tree")
        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(api._budget.requests, 1)

    def test_transport_rejects_arbitrary_urls_and_non_sha_routes(self) -> None:
        api = evidence.GitHubTransport(None, evidence.Budget(time.monotonic()), lambda _: b"{}")
        for route in (
            "https://evil.example/repos/owner/repo/git/trees/" + "a" * 40,
            "/repos/owner/repo/git/trees/../" + "a" * 40,
            "/repos/owner/repo/git/trees/not-a-sha",
            "/repos/owner/repo/git/blobs/" + "a" * 40 + "?redirect=1",
        ):
            with (
                self.subTest(route=route),
                self.assertRaisesRegex(evidence.EvidenceError, "endpoint_rejected"),
            ):
                api.get_json(route, "tree")

    def test_diagnostic_transport_failure_persists_sanitized_counters(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "diagnostic.json"
        calls = 0
        secret = "token-must-never-be-written"

        def responder(url: str) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError(f"{secret} private transport text")
            tree_sha = url.split("/trees/", 1)[1].split("?", 1)[0]
            return response({"sha": tree_sha, "tree": [], "truncated": False})

        receipt = evidence.run_diagnostic(
            LOCK, CHECKSUMS, target, token=secret, responder=responder
        )
        self.assertTrue(target.exists())
        self.assertEqual(receipt["outcome"], "incomplete")
        self.assertEqual(receipt["error_code"], "synthetic_transport_failure")
        self.assertEqual(receipt["counters"]["requests"], 2)
        self.assertEqual(receipt["counters"]["responses"], 1)
        self.assertIsNone(receipt["counters"]["response_bytes"])
        self.assertEqual(
            receipt["counters"]["response_bytes_lower_bound"],
            len(
                response(
                    {
                        "sha": "0" * 40,
                        "tree": [],
                        "truncated": False,
                    }
                )
            ),
        )
        serialized = target.read_text()
        self.assertNotIn(secret, serialized)
        self.assertNotIn("private transport text", serialized)
        self.assertEqual(receipt["attempts"][1]["error_class"], "synthetic_transport_error")
        self.assertIsNone(receipt["attempts"][1]["response_status"])
        self.assertEqual(receipt["limits"]["requests"], 25)
        self.assertEqual(len(receipt["source_ids"]["lock"]), len("sha256:") + 64)

    def test_diagnostic_receipt_no_clobber(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "diagnostic.json"
        target.write_text("keep")
        with self.assertRaisesRegex(evidence.EvidenceError, "receipt_exists_no_clobber"):
            evidence._publish_diagnostic_receipt(target, {"receipt_schema_version": 1})
        self.assertEqual(target.read_text(), "keep")

    def test_diagnostic_http_failure_records_status_without_body(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "diagnostic.json"
        secret_body = b"private token response body"

        class FailingOpener:
            def open(self, request: evidence.urllib.request.Request, timeout: int) -> bytes:
                del timeout
                raise evidence.urllib.error.HTTPError(
                    request.full_url, 503, "unavailable", {}, io.BytesIO(secret_body)
                )

        with patch.object(evidence.urllib.request, "build_opener", return_value=FailingOpener()):
            receipt = evidence.run_diagnostic(LOCK, CHECKSUMS, target, token="private-token")
        self.assertEqual(receipt["error_code"], "github_transport_failure")
        self.assertEqual(receipt["counters"]["requests"], 1)
        self.assertEqual(receipt["counters"]["responses"], 1)
        self.assertEqual(receipt["attempts"][0]["response_status"], 503)
        self.assertEqual(receipt["attempts"][0]["response_bytes"], len(secret_body))
        self.assertEqual(receipt["attempts"][0]["error_class"], "http_error")
        self.assertNotIn(secret_body.decode(), target.read_text())
        self.assertNotIn("private-token", target.read_text())

    def test_diagnostic_request_cap_and_canonical_frozen_identity(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "diagnostic.json"

        def responder(url: str) -> bytes:
            tree_sha = url.split("/trees/", 1)[1].split("?", 1)[0]
            return response({"sha": tree_sha, "tree": [], "truncated": False})

        receipt = evidence.run_diagnostic(LOCK, CHECKSUMS, target, responder=responder)
        self.assertEqual(receipt["outcome"], "incomplete")
        self.assertEqual(receipt["error_code"], "request_budget_exhausted")
        self.assertEqual(receipt["counters"]["requests"], 25)
        self.assertEqual(len(receipt["attempts"]), 25)
        lock, digest = evidence.frozen.load_lock(
            LOCK,
            EXPANSION / "projects-50-v1.json",
            EXPANSION / "longlist-60-v1.json",
            CHECKSUMS,
        )
        self.assertEqual(receipt["source_ids"]["lock"], digest)
        identities = [
            {key: row[key] for key in ("repository", "pr", "base_sha", "head_sha")}
            for row in lock["records"]
        ]
        expected_identity = evidence._sha256(
            json.dumps(identities, sort_keys=True, separators=(",", ":")).encode()
        )
        self.assertEqual(receipt["canonical_identity_sha256"], f"sha256:{expected_identity}")

    def test_diagnostic_per_response_cap_is_strict(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "diagnostic.json"
        receipt = evidence.run_diagnostic(
            LOCK,
            CHECKSUMS,
            target,
            responder=lambda _: b"x" * (evidence.DIAGNOSTIC_MAX_RESPONSE_BYTES + 1),
        )
        self.assertEqual(receipt["error_code"], "response_limit_exceeded")
        self.assertEqual(receipt["counters"]["requests"], 2)
        self.assertEqual(
            receipt["attempts"][0]["response_bytes"],
            evidence.DIAGNOSTIC_MAX_RESPONSE_BYTES + 1,
        )
        self.assertEqual(
            receipt["attempts"][1]["response_bytes"],
            evidence.DIAGNOSTIC_MAX_RESPONSE_BYTES + 1,
        )

    def test_normal_transport_failure_persists_attempt_receipt(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "facts.json"
        receipt_path = directory / "facts.json.attempts.json"
        calls = 0
        secret = "credential and private error detail"

        def responder(url: str) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError(secret)
            tree_sha = url.split("/trees/", 1)[1].split("?", 1)[0]
            return response({"sha": tree_sha, "tree": [], "truncated": False})

        with self.assertRaisesRegex(evidence.EvidenceError, "synthetic_transport_failure"):
            evidence.run(LOCK, CHECKSUMS, target, responder=responder)
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["profile"], "gh103-source-v1")
        self.assertEqual(receipt["outcome"], "incomplete")
        self.assertEqual(receipt["counters"]["requests"], 2)
        self.assertEqual(receipt["counters"]["responses"], 1)
        self.assertIsNone(receipt["counters"]["response_bytes"])
        self.assertEqual(
            receipt["counters"]["response_bytes_lower_bound"],
            len(response({"sha": "0" * 40, "tree": [], "truncated": False})),
        )
        self.assertEqual(receipt["authenticated_lock_record_count"], 100)
        self.assertEqual(receipt["limits"]["detection_bytes_per_response"], 1)
        self.assertFalse(target.exists())
        self.assertNotIn(secret, receipt_path.read_text())

    def test_partial_read_failure_marks_unknown_instead_of_zero(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "diagnostic.json"

        class FailingResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return self.url

            def read(self, _size):
                raise OSError("sensitive read detail")

        class FailingOpener:
            def open(self, request, timeout):
                del timeout
                response_obj = FailingResponse()
                response_obj.url = request.full_url
                return response_obj

        with patch.object(evidence.urllib.request, "build_opener", return_value=FailingOpener()):
            receipt = evidence.run_diagnostic(LOCK, CHECKSUMS, target, token="private-token")
        attempt = receipt["attempts"][0]
        self.assertEqual(attempt["response_status"], 200)
        self.assertIsNone(attempt["response_bytes"])
        self.assertFalse(attempt["response_bytes_complete"])
        self.assertIsNone(receipt["counters"]["response_bytes"])
        self.assertEqual(receipt["counters"]["response_bytes_lower_bound"], 0)
        self.assertFalse(receipt["counters"]["response_bytes_complete"])
        self.assertNotIn("sensitive read detail", target.read_text())
        self.assertNotIn("private-token", target.read_text())

    def test_aggregate_byte_read_uses_remaining_capacity_plus_detection(self) -> None:
        budget = evidence.Budget(
            time.monotonic(), max_response_bytes=100, max_total_bytes=9, attempts=[]
        )
        payloads = iter((b'{"a":1}', b"x" * 50))
        transport = evidence.GitHubTransport(None, budget, lambda _url: next(payloads))
        route = "/repos/owner/repo/git/trees/" + "a" * 40
        self.assertEqual(transport.get_json(route, "tree"), {"a": 1})
        with self.assertRaisesRegex(evidence.EvidenceError, "response_byte_budget_exhausted"):
            transport.get_json(route, "tree")
        self.assertEqual(budget.attempts[1]["response_bytes"], 3)
        self.assertEqual(budget.response_bytes, 10)

    def test_http_error_read_is_bounded_by_aggregate_capacity(self) -> None:
        budget = evidence.Budget(
            time.monotonic(), max_response_bytes=100, max_total_bytes=9, attempts=[]
        )

        class ErrorOpener:
            def open(self, request, timeout):
                del timeout
                raise evidence.urllib.error.HTTPError(
                    request.full_url, 503, "private reason", {}, io.BytesIO(b"x" * 50)
                )

        with patch.object(evidence.urllib.request, "build_opener", return_value=ErrorOpener()):
            transport = evidence.GitHubTransport(None, budget)
            with self.assertRaisesRegex(evidence.EvidenceError, "response_byte_budget_exhausted"):
                transport.get_json("/repos/owner/repo/git/trees/" + "a" * 40, "tree")
        self.assertEqual(budget.attempts[0]["response_status"], 503)
        self.assertEqual(budget.attempts[0]["response_bytes"], 10)

    def test_normal_receipt_no_clobber(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "facts.json"
        receipt = directory / "facts.json.attempts.json"
        receipt.write_text("preserve")
        calls = 0

        def responder(_url: str) -> bytes:
            nonlocal calls
            calls += 1
            return b"not used"

        with self.assertRaisesRegex(evidence.EvidenceError, "receipt_exists_no_clobber"):
            evidence.run(LOCK, CHECKSUMS, target, responder=responder)
        self.assertEqual(calls, 0)
        self.assertEqual(receipt.read_text(), "preserve")

    def test_diagnostic_receipt_collision_preflights_before_transport(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        receipt = directory / "diagnostic.json"
        receipt.write_bytes(b"preserve\x00bytes")
        calls = 0

        def responder(_url: str) -> bytes:
            nonlocal calls
            calls += 1
            return b"not used"

        with self.assertRaisesRegex(evidence.EvidenceError, "receipt_exists_no_clobber"):
            evidence.run_diagnostic(LOCK, CHECKSUMS, receipt, responder=responder)
        self.assertEqual(calls, 0)
        self.assertEqual(receipt.read_bytes(), b"preserve\x00bytes")

    def test_frozen_policy_paths_preflight_in_both_modes(self) -> None:
        policy_bytes = evidence.POLICY_PROFILE.read_bytes()
        calls = 0

        def responder(_url: str) -> bytes:
            nonlocal calls
            calls += 1
            return b"not used"

        with self.assertRaisesRegex(evidence.EvidenceError, "output_is_frozen_input"):
            evidence.run(LOCK, CHECKSUMS, evidence.POLICY_PROFILE, responder=responder)
        with self.assertRaisesRegex(evidence.EvidenceError, "output_is_frozen_input"):
            evidence.run_diagnostic(LOCK, CHECKSUMS, evidence.POLICY_PROFILE, responder=responder)
        self.assertEqual(calls, 0)
        self.assertEqual(evidence.POLICY_PROFILE.read_bytes(), policy_bytes)

    def test_derived_receipt_cannot_clobber_policy_in_either_mode(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        output = directory / "facts.json"
        receipt = output.with_name(output.name + ".attempts.json")
        receipt.write_bytes(b"policy bytes")
        calls = 0

        def responder(_url: str) -> bytes:
            nonlocal calls
            calls += 1
            return b"not used"

        with patch.object(evidence, "POLICY_PROFILE", receipt):
            with self.assertRaisesRegex(evidence.EvidenceError, "output_is_frozen_input"):
                evidence.run(LOCK, CHECKSUMS, output, responder=responder)
            with self.assertRaisesRegex(evidence.EvidenceError, "output_is_frozen_input"):
                evidence.run_diagnostic(LOCK, CHECKSUMS, receipt, responder=responder)
        self.assertEqual(calls, 0)
        self.assertEqual(receipt.read_bytes(), b"policy bytes")

    def test_receipt_race_preserves_original_failure_and_foreign_bytes(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "facts.json"
        receipt = target.with_name(target.name + ".attempts.json")
        foreign = b"created by another process"

        def responder(_url: str) -> bytes:
            receipt.write_bytes(foreign)
            raise evidence.EvidenceError("synthetic_transport_failure")

        with self.assertRaisesRegex(evidence.EvidenceError, "synthetic_transport_failure"):
            evidence.run(LOCK, CHECKSUMS, target, responder=responder)
        self.assertEqual(receipt.read_bytes(), foreign)
        self.assertFalse(target.exists())

    def test_unexpected_exception_is_sanitized_after_receipt_and_in_cli(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        secret = "Authorization=Bearer secret https://private.invalid body=private"
        output = directory / "api.json"
        with (
            patch.object(evidence, "build_report", side_effect=RuntimeError(secret)),
            self.assertRaisesRegex(evidence.EvidenceError, "unexpected_collector_error"),
        ):
            evidence.run(LOCK, CHECKSUMS, output, responder=lambda _: b"unused")
        api_receipt = output.with_name(output.name + ".attempts.json")
        api_bytes = api_receipt.read_bytes()
        self.assertIn(b"unexpected_collector_error", api_bytes)
        self.assertNotIn(secret.encode(), api_bytes)

        cli_output = directory / "cli.json"
        with (
            patch.object(evidence, "build_report", side_effect=RuntimeError(secret)),
            patch(
                "sys.argv",
                [
                    "expansion_source_evidence",
                    "--lock",
                    str(LOCK),
                    "--checksums",
                    str(CHECKSUMS),
                    "--output",
                    str(cli_output),
                ],
            ),
            redirect_stdout(StringIO()) as stdout,
            redirect_stderr(StringIO()) as stderr,
        ):
            self.assertEqual(evidence.main(), 2)
        cli_text = stdout.getvalue() + stderr.getvalue()
        self.assertIn("unexpected_collector_error", cli_text)
        self.assertNotIn(secret, cli_text)
        cli_receipt = cli_output.with_name(cli_output.name + ".attempts.json")
        self.assertNotIn(secret.encode(), cli_receipt.read_bytes())

    def test_base_exception_still_propagates(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        output = directory / "facts.json"
        with (
            patch.object(evidence, "build_report", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            evidence.run(LOCK, CHECKSUMS, output, responder=lambda _: b"unused")
        self.assertFalse(output.with_name(output.name + ".attempts.json").exists())

    def test_invalid_utf8_and_complete_absence_have_different_statuses(self) -> None:
        ref = {"sha": "6" * 40, "size": 1}
        malformed = evidence._group_result(
            "license",
            ["LICENSE"],
            {"LICENSE"},
            0,
            True,
            {"LICENSE": (ref, b"\xff")},
            "a" * 40,
            [],
            {},
        )
        absent = evidence._group_result("license", [], set(), 0, True, {}, "a" * 40, [], {})
        self.assertEqual(malformed["status"], "uncertain")
        self.assertEqual(malformed["reason_codes"], ["invalid_utf8"])
        self.assertEqual(absent["status"], "missing")

    def test_existing_output_is_never_clobbered(self) -> None:
        directory = self.enterContext(__import__("tempfile").TemporaryDirectory())
        target = Path(directory) / "existing.json"
        target.write_text("keep")
        with self.assertRaisesRegex(evidence.EvidenceError, "output_exists_no_clobber"):
            evidence._publish(target, {"x": 1}, {}, "sha256:" + "0" * 64)
        self.assertEqual(target.read_text(), "keep")

    def test_tampered_lock_fails_before_artifact_publication(self) -> None:
        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        expansion = directory / "expansion"
        expansion.mkdir()
        for name in (
            "pr-lock-100-v1.json",
            "projects-50-v1.json",
            "longlist-60-v1.json",
            "checksums-v1.json",
        ):
            copyfile(EXPANSION / name, expansion / name)
        lock_path = expansion / "pr-lock-100-v1.json"
        raw = bytearray(lock_path.read_bytes())
        offset = raw.index(b'"base_sha": "') + len(b'"base_sha": "')
        raw[offset] = ord("0") if raw[offset] != ord("0") else ord("1")
        lock_path.write_bytes(raw)
        target = directory / "not-published.json"
        with self.assertRaisesRegex(evidence.EvidenceError, "frozen_input_authentication_failed"):
            evidence.run(
                lock_path, expansion / "checksums-v1.json", target, responder=lambda _: b"{}"
            )
        self.assertFalse(target.exists())

    def test_report_size_exhaustion_leaves_no_artifact(self) -> None:
        tree_sha = "1" * 40

        def responder(_url: str) -> bytes:
            return response({"sha": tree_sha, "tree": [], "truncated": False})

        directory = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        target = directory / "too-large.json"
        with (
            patch.object(evidence, "MAX_REPORT_BYTES", 1),
            self.assertRaisesRegex(evidence.EvidenceError, "report_size_budget_exhausted"),
        ):
            evidence.run(LOCK, CHECKSUMS, target, responder=responder)
        self.assertFalse(target.exists())

    def test_candidate_limit_is_uncertain_not_missing(self) -> None:
        paths = [f"LICENSE-{index}" for index in range(7)]
        selected = set(paths[:6])
        raw = b"SPDX-License-Identifier: MIT\n"
        entry = {"sha": evidence._git_blob_sha(raw), "size": len(raw)}
        contents = dict.fromkeys(selected, (entry, raw))
        result = evidence._group_result(
            "license", paths, selected, 1, True, contents, "a" * 40, [], {}
        )
        self.assertEqual(result["status"], "uncertain")
        self.assertIn("candidate_limit", result["reason_codes"])
        self.assertEqual(result["omitted_candidate_count"], 1)

    def test_global_walk_budget_failure_leaves_no_output(self) -> None:
        root_sha = "9" * 40
        children = [
            {"path": f"sub-{index}", "type": "tree", "sha": f"{index + 1:040x}"}
            for index in range(101)
        ]

        def responder(url: str) -> bytes:
            if "?recursive=1" in url:
                return response({"sha": root_sha, "truncated": True, "tree": []})
            if url.endswith(f"/trees/{root_sha}"):
                return response({"sha": root_sha, "tree": children, "truncated": False})
            tree_sha = url.rsplit("/", 1)[-1]
            return response({"sha": tree_sha, "tree": [], "truncated": False})

        directory = self.enterContext(__import__("tempfile").TemporaryDirectory())
        target = Path(directory) / "must-not-exist.json"
        with self.assertRaisesRegex(evidence.EvidenceError, "overhead_request_budget_exhausted"):
            evidence.run(LOCK, CHECKSUMS, target, responder=responder)
        self.assertFalse(target.exists())

    def test_duplicate_json_keys_and_unsafe_paths_fail_closed(self) -> None:
        with self.assertRaisesRegex(evidence.EvidenceError, "duplicate_json_key"):
            evidence._unique_object([("sha", "a"), ("sha", "b")])
        for path in ("../LICENSE", "/LICENSE", "a//b", "a/./b", "a/../b"):
            self.assertFalse(evidence._safe_path(path))

    def test_recursive_page_finite_http_outcomes_remain_uncertain(self) -> None:
        tree_sha = "1" * 40
        body = b"finite page status"
        for status in (301, 404, 410):
            budget = evidence.Budget(time.monotonic(), attempts=[])

            def responder(url: str, code: int = status) -> bytes:
                if url.endswith("?recursive=1"):
                    return response({"sha": tree_sha, "tree": [], "truncated": True})
                raise urllib.error.HTTPError(url, code, "synthetic", {}, io.BytesIO(body))

            with self.subTest(status=status):
                side = evidence.collect_side(
                    "owner/repo", "2" * 40, evidence.GitHubTransport(None, budget, responder)
                )
                for group in side.values():
                    self.assertEqual(group["status"], "uncertain")
                    self.assertIn("tree_page_unavailable", group["reason_codes"])
                    self.assertIn(f"source_unavailable_http_{status}", group["reason_codes"])
                    self.assertIsNone(group["unknown_count"])
                    self.assertEqual(group["candidate_count"], 0)
                    self.assertEqual(group["omitted_candidate_count"], 0)
                    self.assertEqual(group["facts"], [])
                self.assertEqual(budget.requests, 2)
                self.assertEqual(
                    [attempt["response_status"] for attempt in budget.attempts],
                    [200, status],
                )

    def test_recursive_page_auth_and_transport_http_fail_closed(self) -> None:
        tree_sha = "1" * 40
        for status in (401, 403, 302, 429, 500):
            budget = evidence.Budget(time.monotonic(), attempts=[])

            def responder(url: str, code: int = status) -> bytes:
                if url.endswith("?recursive=1"):
                    return response({"sha": tree_sha, "tree": [], "truncated": True})
                raise urllib.error.HTTPError(url, code, "synthetic", {}, io.BytesIO(b"failure"))

            error = f"github_http_{status}" if status in (401, 403) else "github_transport_failure"
            with self.subTest(status=status), self.assertRaisesRegex(evidence.EvidenceError, error):
                evidence.collect_side(
                    "owner/repo", "2" * 40, evidence.GitHubTransport(None, budget, responder)
                )
            self.assertEqual(budget.requests, 2)

    def test_recursive_page_redirect_and_network_errors_fail_closed(self) -> None:
        tree_sha = "1" * 40

        class SyntheticResponse:
            status = 200

            def __init__(self, url: str, raw: bytes) -> None:
                self.url = url
                self.raw = raw

            def __enter__(self) -> SyntheticResponse:
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            def geturl(self) -> str:
                return self.url

            def read(self, limit: int) -> bytes:
                return self.raw[:limit]

        class SyntheticOpener:
            def __init__(self, failure: str) -> None:
                self.failure = failure

            def open(self, request: object, timeout: int) -> SyntheticResponse:
                del timeout
                url = request.full_url
                if url.endswith("?recursive=1"):
                    return SyntheticResponse(
                        url, response({"sha": tree_sha, "tree": [], "truncated": True})
                    )
                if self.failure == "network":
                    raise urllib.error.URLError("synthetic transport error")
                return SyntheticResponse("https://untrusted.invalid/tree", b"{}")

        for mode, error in (
            ("network", "github_transport_failure"),
            ("redirect", "redirect_rejected"),
        ):
            budget = evidence.Budget(time.monotonic(), attempts=[])
            with (
                self.subTest(mode=mode),
                patch.object(
                    evidence.urllib.request, "build_opener", return_value=SyntheticOpener(mode)
                ),
                self.assertRaisesRegex(evidence.EvidenceError, error),
            ):
                evidence.collect_side(
                    "owner/repo", "2" * 40, evidence.GitHubTransport(None, budget)
                )
            self.assertEqual(budget.requests, 2)

    def test_recursive_page_response_limit_keeps_partial_recovery(self) -> None:
        tree_sha = "1" * 40
        budget = evidence.Budget(time.monotonic(), max_response_bytes=1024, attempts=[])

        def responder(url: str) -> bytes:
            if url.endswith("?recursive=1"):
                return response({"sha": tree_sha, "tree": [], "truncated": True})
            return b"x" * 2048

        side = evidence.collect_side(
            "owner/repo", "2" * 40, evidence.GitHubTransport(None, budget, responder)
        )
        for group in side.values():
            self.assertEqual(group["status"], "uncertain")
            self.assertIn("tree_page_unavailable", group["reason_codes"])
            self.assertEqual(group["unknown_count"], 0)
            self.assertEqual(group["facts"], [])
        self.assertEqual(budget.requests, 2)
        self.assertEqual(budget.attempts[-1]["error_class"], "response_limit_exceeded")

    def test_verified_source_schema_requires_nonnegative_integer_size(self) -> None:
        schema = json.loads((EXPANSION / "source-evidence-v2.schema.json").read_text())
        self.assertEqual(
            schema["$defs"]["source"]["properties"]["size"], {"type": "integer", "minimum": 0}
        )

    def test_serialized_verified_source_rejects_null_size(self) -> None:
        lock, lock_hash = evidence.frozen.load_lock(
            LOCK, EXPANSION / "projects-50-v1.json", EXPANSION / "longlist-60-v1.json", CHECKSUMS
        )
        raw = b"SPDX-License-Identifier: MIT\n"
        blob_sha = evidence._git_blob_sha(raw)
        tree_sha = "1" * 40

        def responder(url: str) -> bytes:
            if "/git/trees/" in url:
                return response(
                    {
                        "sha": tree_sha,
                        "truncated": False,
                        "tree": [
                            {"path": "LICENSE", "type": "blob", "sha": blob_sha, "size": len(raw)}
                        ],
                    }
                )
            return response(
                {
                    "sha": blob_sha,
                    "size": len(raw),
                    "encoding": "base64",
                    "content": base64.b64encode(raw).decode(),
                }
            )

        budget = evidence.Budget(time.monotonic())
        report = evidence.build_report(
            lock,
            {
                "lock": lock_hash,
                "manifest": lock["manifest_hash"],
                "longlist": lock["longlist_hash"],
            },
            evidence.GitHubTransport(None, budget, responder),
            budget,
        )
        evidence.validate_report(report, lock, lock_hash)
        malformed = copy.deepcopy(report)
        malformed["records"][0]["base"]["license"]["sources"][0]["size"] = None
        with self.assertRaisesRegex(evidence.EvidenceError, "report_source_identity_invalid"):
            evidence._validate_serialized_report(malformed)
        with self.assertRaisesRegex(evidence.EvidenceError, "report_source_identity_invalid"):
            evidence.validate_report(malformed, lock, lock_hash)


if __name__ == "__main__":
    unittest.main()
