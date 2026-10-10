#!/usr/bin/env python3
"""Bounded read-only source metadata evidence at frozen GH103 survey commits.

Upstream bytes are untrusted data. This program never imports or executes them.
"""
from __future__ import annotations

import argparse
import ast
import base64
import configparser
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ImportError:  # Python 3.10: a missing parser is not malformed source.
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[2]
EXP = ROOT / "benchmarks/real_world/expansion"
OUT = ROOT / "benchmarks/results/gh103-source-metadata-v3"
V1_HASH = "194afecc671535639cf51b4b98e6fbe2d36a6159c882de1ae2bd3a4df1a28fe0"
V2_HASH = "abd4ee6418a70bf1963a379b26d3ddaf1fe43b2a5a5b60f4090801d1ac5dbc1c"
MAX_REQUESTS = 1200
MAX_BYTES = 128 * 1024 * 1024
MAX_OBJECTS = 1200
MAX_FILE = 512 * 1024
MAX_BLOB_RESPONSE = 4 * ((MAX_FILE + 2) // 3) + 8192
MAX_FILES_PER_PROJECT = 24
MAX_PROJECT_BYTES = 6 * 1024 * 1024
MAX_RESULT_BYTES = 192 * 1024 * 1024
MAX_WALL = 900
TIMEOUT = 15
RETRIES = 2
API_ORIGIN = "https://api.github.com"
PACKAGE_NAMES = {"pyproject.toml", "setup.cfg", "setup.py", "tox.ini", "Pipfile"}
LICENSE_NAMES = {"LICENSE", "COPYING", "COPYRIGHT"}
INTEGRITY_BASIS = "raw GitHub REST response snapshots over HTTPS to api.github.com; Git tree and blob object IDs are recomputed; commit identity is checked against the frozen SHA and relies on GitHub/TLS as external authority; no independent signature is claimed"


class EvidenceError(ValueError):
    pass


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise EvidenceError("duplicate_json_key")
        out[key] = value
    return out


def _constant(value):
    raise EvidenceError("nonfinite_json_number")


def decode_json(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)


def load_json(path: Path) -> tuple[Any, bytes]:
    if path.stat().st_size > MAX_RESULT_BYTES:
        raise EvidenceError("input_result_too_large")
    raw = path.read_bytes()
    return decode_json(raw), raw


def population() -> tuple[list[dict[str, str]], dict[str, str]]:
    m1, b1 = load_json(EXP / "projects-50-v1.json")
    m2, b2 = load_json(EXP / "projects-50x50-v2.json")
    if hashlib.sha256(b1).hexdigest() != V1_HASH or hashlib.sha256(b2).hexdigest() != V2_HASH:
        raise EvidenceError("frozen_population_hash_mismatch")
    a = {p["repository"]: p["survey_commit"] for p in m1["projects"]}
    b = {p["repository"]: p["survey_commit"] for p in m2["projects"]}
    if len(a) != 50 or len(b) != 50 or a != b:
        raise EvidenceError("frozen_population_mismatch")
    return [{"repository": r, "survey_commit": c} for r, c in b.items()], {
        "v1": "sha256:" + V1_HASH, "v2": "sha256:" + V2_HASH,
    }


def _git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def _git_tree_sha(entries: list[dict[str, Any]]) -> str:
    """Recompute every recursive Git tree object from the GitHub tree listing."""
    children: dict[str, list[tuple[str, str, str, str]]] = {"": []}
    directories: dict[str, str] = {"": ""}
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise EvidenceError("tree_entry_malformed")
        path = entry.get("path")
        mode, kind, sha = entry.get("mode"), entry.get("type"), entry.get("sha")
        if not _safe_tree_path(path) or path in seen:
            raise EvidenceError("tree_path_invalid_or_duplicate")
        seen.add(path)
        if mode not in {"040000", "100644", "100755", "120000", "160000"}:
            raise EvidenceError("tree_mode_invalid")
        if kind not in {"tree", "blob", "commit"} or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise EvidenceError("tree_object_identity_invalid")
        if (kind == "tree" and mode != "040000") or (kind == "commit" and mode != "160000"):
            raise EvidenceError("tree_type_mode_mismatch")
        parts = path.split("/")
        parent = "/".join(parts[:-1])
        name = parts[-1]
        if parent and parent not in directories:
            raise EvidenceError("tree_parent_missing")
        children.setdefault(parent, []).append((name, mode, kind, sha))
        if kind == "tree":
            directories[path] = sha
            children.setdefault(path, [])
        elif kind == "commit" and mode != "160000":
            raise EvidenceError("tree_gitlink_mode_mismatch")
        elif kind == "blob" and mode in {"040000", "160000"}:
            raise EvidenceError("tree_blob_mode_mismatch")

    def digest(directory: str) -> str:
        records = children.get(directory, [])
        ordered = sorted(records, key=lambda item: item[0].encode("utf-8") + (b"/" if item[2] == "tree" else b""))
        body = bytearray()
        for name, mode, kind, claimed_sha in ordered:
            child_path = f"{directory}/{name}" if directory else name
            object_sha = digest(child_path) if kind == "tree" else claimed_sha
            if kind == "tree" and object_sha != claimed_sha:
                raise EvidenceError("nested_tree_hash_mismatch")
            wire_mode = "40000" if mode == "040000" else mode
            body.extend(wire_mode.encode("ascii") + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(object_sha))
        raw = bytes(body)
        return hashlib.sha1(b"tree " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()

    return digest("")


def _safe_repo(repository: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository))


def _safe_tree_path(path: str) -> bool:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def get_auth_token() -> tuple[str | None, str]:
    env_token = os.environ.get("GITHUB_TOKEN")
    if env_token:
        return env_token.strip(), "GITHUB_TOKEN"
    try:
        # Capture token in process memory only. Never interpolate it into a command,
        # URL, exception, stdout, stderr, or collection record.
        proc = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            check=False, capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, "unauthenticated"
    if proc.returncode or not proc.stdout.strip():
        return None, "unauthenticated"
    token = proc.stdout.strip()
    if "\n" in token or "\r" in token:
        return None, "unauthenticated"
    return token, "gh_auth_profile"


class Client:
    """Fixed-origin API client with strict aggregate accounting and no redirects."""

    def __init__(self, token: str | None):
        self._token = token
        self.started = time.monotonic()
        self.requests = 0
        self.response_bytes = 0
        self.objects = 0
        self.retries = 0
        self.request_log: list[dict[str, Any]] = []
        self.cache: dict[str, bytes] = {}

    def _remaining_wall(self) -> float:
        remaining = MAX_WALL - (time.monotonic() - self.started)
        if remaining <= 0:
            raise EvidenceError("wall_budget_exhausted")
        return remaining

    def get(self, url: str, limit: int) -> bytes:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "https" or parsed.netloc != "api.github.com"
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or not parsed.path.startswith("/repos/")
        ):
            raise EvidenceError("request_origin_rejected")
        if url in self.cache:
            return self.cache[url]
        for attempt in range(RETRIES + 1):
            remaining_wall = self._remaining_wall()
            if self.requests >= MAX_REQUESTS:
                raise EvidenceError("request_budget_exhausted")
            if self.objects >= MAX_OBJECTS:
                raise EvidenceError("object_budget_exhausted")
            remaining_bytes = MAX_BYTES - self.response_bytes
            if remaining_bytes <= 0:
                raise EvidenceError("response_byte_budget_exhausted")
            per_response = min(limit, remaining_bytes)
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/vnd.github+json", "User-Agent": "GH103-source-metadata-v3"},
            )
            if self._token:
                req.add_header("Authorization", "Bearer " + self._token)
            self.requests += 1
            if attempt:
                self.retries += 1
            timeout = min(TIMEOUT, max(0.1, remaining_wall))
            response = None
            try:
                response = urllib.request.build_opener(_NoRedirect()).open(req, timeout=timeout)
                raw = response.read(per_response)
                self.response_bytes += len(raw)
                if len(raw) >= per_response:
                    content_length = response.headers.get("Content-Length")
                    try:
                        declared_length = int(content_length) if content_length is not None else None
                    except ValueError:
                        declared_length = None
                    # Never probe one byte beyond the byte budget. When the
                    # bounded read fills its cap, only a smaller declared body
                    # proves that the complete response fitted.
                    if per_response < limit or declared_length is None or declared_length > per_response:
                        self.request_log.append({"url": url, "attempt": attempt + 1, "status": "truncated", "bytes": len(raw)})
                        raise EvidenceError("response_truncated_or_byte_budget_exhausted")
                self.request_log.append({"url": url, "attempt": attempt + 1, "status": "success", "bytes": len(raw)})
                self.objects += 1
                self.cache[url] = raw
                return raw
            except http.client.IncompleteRead as exc:
                partial = exc.partial or b""
                self.response_bytes += len(partial)
                self.request_log.append({"url": url, "attempt": attempt + 1, "status": "truncated", "bytes": len(partial)})
                if attempt < RETRIES:
                    time.sleep(min(2 ** attempt, 4, self._remaining_wall()))
                    continue
                raise EvidenceError("response_truncated") from None
            except urllib.error.HTTPError as exc:
                try:
                    body = exc.read(min(4096, max(0, MAX_BYTES - self.response_bytes)))
                    self.response_bytes += len(body)
                finally:
                    exc.close()
                self.request_log.append({"url": url, "attempt": attempt + 1, "status": f"http_{exc.code}", "bytes": len(body)})
                if exc.code in (301, 302, 303, 307, 308):
                    raise EvidenceError("redirect_rejected") from None
                if exc.code in (429, 500, 502, 503, 504) and attempt < RETRIES:
                    delay = min(2 ** attempt, 4, self._remaining_wall())
                    time.sleep(delay)
                    continue
                raise EvidenceError(f"http_{exc.code}") from None
            except (urllib.error.URLError, TimeoutError, OSError):
                self.request_log.append({"url": url, "attempt": attempt + 1, "status": "network_unavailable", "bytes": 0})
                if attempt < RETRIES:
                    time.sleep(min(2 ** attempt, 4, self._remaining_wall()))
                    continue
                raise EvidenceError("network_unavailable") from None
            finally:
                if response is not None:
                    response.close()
        raise EvidenceError("retry_exhausted")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _snapshot(url: str, raw: bytes) -> dict[str, Any]:
    return {"request_url": url, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_base64": base64.b64encode(raw).decode("ascii")}


def _read_snapshot(snapshot: Any, expected_url: str, *, parse: bool = True) -> tuple[bytes, Any]:
    if not isinstance(snapshot, dict) or set(snapshot) != {"request_url", "bytes", "sha256", "raw_base64"}:
        raise EvidenceError("snapshot_schema_invalid")
    if snapshot["request_url"] != expected_url:
        raise EvidenceError("snapshot_request_url_mismatch")
    raw = base64.b64decode(snapshot["raw_base64"], validate=True)
    if len(raw) != snapshot["bytes"] or hashlib.sha256(raw).hexdigest() != snapshot["sha256"]:
        raise EvidenceError("snapshot_hash_mismatch")
    if not parse:
        return raw, None
    return raw, decode_json(raw)


def _python_literal_list(text: str) -> tuple[str, list[str]]:
    """Parse the common static GitHub Actions Python matrix shapes as text data."""
    matches = list(re.finditer(r"(?m)^(\s*)(?:python-version|python_version)\s*:\s*(.*?)\s*$", text))
    if not matches:
        return "not_declared", []
    found: set[str] = set()
    states: set[str] = set()
    lines = text.splitlines()
    for match in matches:
        value = match.group(2).strip()
        if not value:
            indent = len(match.group(1))
            block_values = []
            for line in lines[text[:match.start()].count("\n") + 1:]:
                item = re.match(r"^(\s*)-\s*(.*?)\s*$", line)
                if item and len(item.group(1)) > indent:
                    block_values.append(item.group(2))
                elif line.strip() and len(line) - len(line.lstrip()) <= indent:
                    break
            value = "[" + ",".join(block_values) + "]" if block_values else ""
        if "${{" in value or "}}" in value:
            states.add("dynamic_expression")
            continue
        value = value.split("#", 1)[0].strip()
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value.strip("'\"")):
            found.add(value.strip("'\""))
            continue
        # GitHub workflow YAML commonly uses unquoted numeric list members.
        inline = re.fullmatch(r"\[\s*([0-9. ,\"']+)\s*\]", value)
        if inline:
            pieces = [p.strip().strip("'\"") for p in inline.group(1).split(",") if p.strip()]
            if pieces and all(re.fullmatch(r"\d+\.\d+(?:\.\d+)?", p) for p in pieces):
                found.update(pieces)
                continue
        try:
            literal = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            states.add("unsupported_expression")
            continue
        values = literal if isinstance(literal, (list, tuple)) else [literal]
        if values and all(isinstance(v, (str, int, float)) and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", str(v)) for v in values):
            found.update(map(str, values))
        else:
            states.add("unsupported_expression")
    if found:
        return "declared", sorted(found)
    if "dynamic_expression" in states:
        return "dynamic_expression", []
    return ("unsupported_expression", []) if states else ("not_declared", [])


def _toml_parse(text: str) -> tuple[str, Any]:
    if tomllib is None:
        return "parser_unavailable", None
    try:
        return "parsed", tomllib.loads(text)
    except Exception as exc:
        # Missing parser support (Python 3.10 without tomli) is not malformed
        # evidence; TOMLDecodeError is checked below when available.
        if tomllib is None or not isinstance(exc, getattr(tomllib, "TOMLDecodeError", ())):
            return "parser_unavailable", None
        return "malformed", None


def parse_metadata(path: str, raw: bytes) -> dict[str, Any]:
    digest = hashlib.sha256(raw).hexdigest()
    base = {"status": "malformed", "sha256": digest, "bytes": len(raw)}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {**base, "reason": "not_utf8"}
    name = PurePosixPath(path).name
    if name.endswith(".toml") or name == "Pipfile":
        status, doc = _toml_parse(text)
        if status != "parsed":
            return {**base, "status": status, "reason": "toml_syntax_error" if status == "malformed" else "toml_parser_unavailable"}
        if name == "Pipfile":
            requires = doc.get("requires", {})
            return {"status": "parsed", "sha256": digest, "bytes": len(raw),
                    "kind": "pipfile", "requires_python": requires.get("python_version", "not_declared"),
                    "dependencies": doc.get("packages", "not_declared"),
                    "development_dependencies": doc.get("dev-packages", "not_declared")}
        project = doc.get("project", {})
        if not isinstance(project, dict):
            return {**base, "status": "malformed", "reason": "project_table_not_table"}
        return {"status": "parsed", "sha256": digest, "bytes": len(raw), "kind": "pyproject",
                "requires_python": project.get("requires-python", "not_declared"),
                "dependencies": project.get("dependencies", "not_declared"),
                "optional_dependencies": project.get("optional-dependencies", "not_declared"),
                "classifiers": project.get("classifiers", "not_declared"),
                "license": project.get("license", "not_declared"),
                "dynamic_fields": project.get("dynamic", [])}
    if name.endswith(".cfg") or name == "tox.ini":
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            parser.read_string(text)
        except configparser.Error:
            return {**base, "reason": "ini_syntax_error"}
        fields: dict[str, Any] = {}
        for key in ("python_requires", "install_requires", "license_file", "license_files"):
            if parser.has_option("options", key):
                fields[key] = parser.get("options", key).strip().splitlines()
        extras = {}
        for section in parser.sections():
            if section.lower() == "options.extras_require":
                extras = {key: value.strip().splitlines() for key, value in parser.items(section)}
        if extras:
            fields["extras_require"] = extras
        classifiers = {}
        if parser.has_option("metadata", "classifiers"):
            classifiers["classifiers"] = parser.get("metadata", "classifiers").strip().splitlines()
        return {"status": "parsed", "sha256": digest, "bytes": len(raw), "kind": "ini",
                "declared_fields": fields, "metadata_fields": classifiers}
    if name == "setup.py":
        try:
            tree = ast.parse(text, filename=path)
        except (SyntaxError, ValueError):
            return {**base, "reason": "python_syntax_error"}
        fields = {}
        allowed = {"python_requires", "install_requires", "extras_require", "classifiers", "license"}
        setup_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setup"]
        dynamic_setup = False
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Name) and call.func.id == "setup":
                    for kw in call.keywords:
                        if kw.arg is None:
                            dynamic_setup = True
                        if kw.arg in allowed:
                            try: fields[kw.arg] = ast.literal_eval(kw.value)
                            except (ValueError, TypeError):
                                fields[kw.arg] = "dynamic_or_nonliteral"
                                dynamic_setup = True
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in allowed:
                        try: fields[target.id] = ast.literal_eval(node.value)
                        except (ValueError, TypeError): fields[target.id] = "dynamic_or_nonliteral"
        return {"status": "parsed", "sha256": digest, "bytes": len(raw), "kind": "setup_ast_literals",
                "declared_fields": fields,
                "setup_call_status": "dynamic_or_unrecognized" if dynamic_setup else "static_call_observed" if setup_calls else "no_setup_call_observed"}
    if name.startswith("requirements") or name.startswith("constraints"):
        requirements = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("#", "-"))]
        return {"status": "parsed", "sha256": digest, "bytes": len(raw), "kind": "requirements_lines", "declared_requirements": requirements}
    if path.startswith(".github/workflows/"):
        status, versions = _python_literal_list(text)
        return {"status": status, "sha256": digest, "bytes": len(raw), "kind": "workflow_python_matrix", "python_versions": versions}
    return {"status": "retrieved", "sha256": digest, "bytes": len(raw), "kind": "license_text"}


def _is_metadata_path(path: str) -> bool:
    name = PurePosixPath(path).name
    return (
        name in PACKAGE_NAMES or name in LICENSE_NAMES
        or name.startswith(("LICENSE-", "LICENSE.", "COPYING-", "COPYING."))
        or name.startswith("requirements") and name.endswith((".txt", ".in"))
        or name.startswith("constraints") and name.endswith((".txt", ".in"))
        or path.startswith(".github/workflows/") and name.endswith((".yml", ".yaml"))
    )


def _candidate_priority(path: str) -> tuple[int, str]:
    """Prioritize package declarations and license evidence before workflows."""
    name = PurePosixPath(path).name
    root = "/" not in path
    if name in PACKAGE_NAMES:
        return (0 if root else 1, path)
    if name in LICENSE_NAMES or name.startswith(("LICENSE-", "LICENSE.", "COPYING-", "COPYING.")):
        return (2 if root else 3, path)
    if name.startswith(("requirements", "constraints")):
        return (4, path)
    lowered = path.lower()
    if path.startswith(".github/workflows/") and any(tag in lowered for tag in ("test", "ci", "python", "build")):
        return (5, path)
    return (6, path)


def _file_error(path: str, blob_sha: str, reason: str) -> dict[str, Any]:
    return {"path": path, "blob_sha": blob_sha, "status": reason}


def collect_project(client: Client, project: dict[str, str]) -> dict[str, Any]:
    repo, commit = project["repository"], project["survey_commit"]
    base = f"{API_ORIGIN}/repos/{repo}"
    commit_url = f"{base}/commits/{commit}"
    result: dict[str, Any] = {"repository": repo, "survey_commit": commit, "status": "unavailable",
                              "failure": None, "commit_evidence": None, "tree_evidence": None,
                              "tree_sha": None, "tree_truncated": None, "candidate_count": None,
                              "candidate_limit": MAX_FILES_PER_PROJECT, "files": []}
    try:
        raw_commit = client.get(commit_url, 2 * 1024 * 1024)
        result["commit_evidence"] = _snapshot(commit_url, raw_commit)
        try:
            commit_doc = decode_json(raw_commit)
        except EvidenceError:
            result.update(status="malformed", failure="commit_response_malformed")
            return result
        if not isinstance(commit_doc, dict) or commit_doc.get("sha") != commit:
            result.update(status="contradictory", failure="requested_commit_identity_mismatch")
            return result
        tree_sha = commit_doc.get("commit", {}).get("tree", {}).get("sha")
        if not isinstance(tree_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", tree_sha):
            raise EvidenceError("commit_tree_identity_malformed")
        result["tree_sha"] = tree_sha
        tree_url = f"{base}/git/trees/{tree_sha}?recursive=1"
        raw_tree = client.get(tree_url, 8 * 1024 * 1024)
        result["tree_evidence"] = _snapshot(tree_url, raw_tree)
        try:
            tree_doc = decode_json(raw_tree)
        except EvidenceError:
            result.update(status="malformed", failure="tree_response_malformed")
            return result
        result["tree_truncated"] = tree_doc.get("truncated") if isinstance(tree_doc, dict) else None
        if not isinstance(tree_doc, dict) or tree_doc.get("sha") != tree_sha:
            result.update(status="contradictory", failure="requested_tree_identity_mismatch")
            return result
        entries = tree_doc.get("tree")
        if not isinstance(entries, list):
            result.update(status="malformed", failure="tree_entries_malformed")
            return result
        if tree_doc.get("truncated") is False and _git_tree_sha(entries) != tree_sha:
            result.update(status="contradictory", failure="tree_content_hash_mismatch")
            return result
        result["candidate_count"] = sum(
            1 for e in entries if isinstance(e, dict) and e.get("type") == "blob"
            and e.get("mode") in ("100644", "100755") and _is_metadata_path(e.get("path", ""))
        )
        if tree_doc.get("truncated") is True:
            result.update(status="truncated", failure="tree_api_truncated")
            return result
        if tree_doc.get("truncated") is not False:
            raise EvidenceError("tree_truncated_flag_missing")
        candidates = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise EvidenceError("tree_entry_malformed")
            path = entry.get("path")
            if not _safe_tree_path(path):
                raise EvidenceError("tree_path_malformed")
            if entry.get("type") == "blob" and entry.get("mode") in ("100644", "100755") and _is_metadata_path(path):
                sha = entry.get("sha")
                if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
                    raise EvidenceError("tree_blob_identity_malformed")
                candidates.append((path, sha))
        candidates.sort(key=lambda pair: _candidate_priority(pair[0]))
        was_file_truncated = len(candidates) > MAX_FILES_PER_PROJECT
        candidates = candidates[:MAX_FILES_PER_PROJECT]
        files: list[dict[str, Any]] = []
        total = 0
        for path, sha in candidates:
            url = f"{base}/git/blobs/{sha}"
            try:
                raw_blob = client.get(url, MAX_BLOB_RESPONSE)
                blob_doc = decode_json(raw_blob)
                if not isinstance(blob_doc, dict) or blob_doc.get("sha") != sha or blob_doc.get("encoding") != "base64":
                    raise EvidenceError("requested_blob_identity_mismatch")
                encoded_content = re.sub(r"\s+", "", blob_doc.get("content", ""))
                raw = base64.b64decode(encoded_content, validate=True)
                if base64.b64encode(raw).decode("ascii") != encoded_content:
                    raise EvidenceError("blob_base64_noncanonical")
                if _git_blob_sha(raw) != sha:
                    raise EvidenceError("requested_blob_content_hash_mismatch")
                if len(raw) > MAX_FILE or total + len(raw) > MAX_PROJECT_BYTES:
                    files.append(_file_error(path, sha, "project_file_budget_exceeded"))
                    continue
                total += len(raw)
                item = {"path": path, "blob_sha": sha, "request_url": url,
                        "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                        "raw_base64": base64.b64encode(raw).decode("ascii"),
                        "parsed": parse_metadata(path, raw)}
                files.append(item)
            except EvidenceError as exc:
                files.append(_file_error(path, sha, str(exc)))
        result["files"] = files
        if was_file_truncated:
            result.update(status="truncated", failure="metadata_file_cap_exceeded")
        elif any("raw_base64" not in item for item in files):
            result.update(status="incomplete", failure="one_or_more_metadata_files_unavailable")
        elif len(files) != result["candidate_count"]:
            result.update(status="incomplete", failure="metadata_file_coverage_mismatch")
        else:
            result["status"] = "complete"
        return result
    except EvidenceError as exc:
        result["failure"] = str(exc)
        if str(exc) in {"response_truncated_or_byte_budget_exhausted", "response_truncated"}:
            result["status"] = "truncated"
        elif str(exc) in {"tree_path_malformed", "tree_entry_malformed", "tree_truncated_flag_missing", "tree_entries_malformed", "tree_path_invalid_or_duplicate", "tree_parent_missing", "tree_mode_invalid", "tree_type_mode_mismatch", "tree_object_identity_invalid", "tree_gitlink_mode_mismatch", "tree_blob_mode_mismatch"}:
            result["status"] = "malformed"
        elif str(exc) in {"requested_commit_identity_mismatch", "requested_tree_identity_mismatch", "tree_content_hash_mismatch"}:
            result["status"] = "contradictory"
        return result
    except (KeyError, TypeError, ValueError):
        result["failure"] = "malformed_api_response"
        return result


def _exact_keys(obj: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != keys:
        raise EvidenceError(label + "_schema_invalid")
    return obj


def _validate_project(project: Any, expected: dict[str, str]) -> set[str]:
    keys = {"repository", "survey_commit", "status", "failure", "commit_evidence", "tree_evidence",
            "tree_sha", "tree_truncated", "candidate_count", "candidate_limit", "files"}
    p = _exact_keys(project, keys, "project")
    if p["repository"] != expected["repository"] or p["survey_commit"] != expected["survey_commit"]:
        raise EvidenceError("project_identity_mismatch")
    if p["status"] not in {"complete", "incomplete", "unavailable", "truncated", "malformed", "contradictory"}:
        raise EvidenceError("project_status_invalid")
    if p["candidate_limit"] != MAX_FILES_PER_PROJECT:
        raise EvidenceError("candidate_limit_mismatch")
    if type(p["candidate_limit"]) is not int:
        raise EvidenceError("candidate_limit_type_invalid")
    files = p["files"]
    base = f"{API_ORIGIN}/repos/{p['repository']}"
    allowed_requests = {f"{base}/commits/{p['survey_commit']}"}
    if not isinstance(files, list) or len(files) > MAX_FILES_PER_PROJECT:
        raise EvidenceError("file_list_invalid")
    commit_doc = None
    if p["commit_evidence"] is not None:
        commit_url = f"{API_ORIGIN}/repos/{p['repository']}/commits/{p['survey_commit']}"
        commit_raw, _ = _read_snapshot(p["commit_evidence"], commit_url, parse=False)
        try:
            commit_doc = decode_json(commit_raw)
        except EvidenceError:
            if p["status"] == "malformed" and p["failure"] == "commit_response_malformed" and p["tree_evidence"] is None and p["tree_sha"] is None and p["files"] == []:
                return allowed_requests
            raise EvidenceError("commit_snapshot_malformed_without_status") from None
        if not isinstance(commit_doc, dict) or commit_doc.get("sha") != p["survey_commit"]:
            if p["status"] == "contradictory" and p["failure"] == "requested_commit_identity_mismatch" and p["tree_evidence"] is None and p["tree_sha"] is None and p["files"] == []:
                return allowed_requests
            raise EvidenceError("commit_snapshot_identity_mismatch")
        commit_tree_sha = commit_doc.get("commit", {}).get("tree", {}).get("sha")
        if commit_tree_sha != p["tree_sha"]:
            raise EvidenceError("commit_tree_sha_mismatch")
        if commit_tree_sha is not None:
            allowed_requests.add(f"{base}/git/trees/{commit_tree_sha}?recursive=1")
    tree_doc = None
    if p["tree_evidence"] is not None and commit_doc is None:
        raise EvidenceError("tree_snapshot_without_commit_snapshot")
    if p["tree_evidence"] is not None:
        if not isinstance(p["tree_sha"], str) or not re.fullmatch(r"[0-9a-f]{40}", p["tree_sha"]):
            raise EvidenceError("tree_sha_invalid")
        tree_url = f"{API_ORIGIN}/repos/{p['repository']}/git/trees/{p['tree_sha']}?recursive=1"
        tree_raw, _ = _read_snapshot(p["tree_evidence"], tree_url, parse=False)
        try:
            tree_doc = decode_json(tree_raw)
        except EvidenceError:
            if p["status"] == "malformed" and p["failure"] == "tree_response_malformed" and p["tree_truncated"] is None and p["candidate_count"] is None and p["files"] == []:
                return allowed_requests
            raise EvidenceError("tree_snapshot_malformed_without_status") from None
        if not isinstance(tree_doc, dict) or tree_doc.get("sha") != p["tree_sha"]:
            if p["status"] == "contradictory" and p["failure"] == "requested_tree_identity_mismatch" and p["candidate_count"] is None and p["files"] == []:
                return allowed_requests
            raise EvidenceError("tree_snapshot_identity_mismatch")
        entries = tree_doc.get("tree")
        if not isinstance(entries, list):
            if p["status"] == "malformed" and p["failure"] == "tree_entries_malformed" and p["candidate_count"] is None and p["files"] == []:
                return allowed_requests
            raise EvidenceError("tree_snapshot_structure_mismatch")
        if tree_doc.get("truncated") is not p["tree_truncated"]:
            raise EvidenceError("tree_snapshot_structure_mismatch")
        if tree_doc.get("truncated") is False:
            try:
                actual_tree_sha = _git_tree_sha(entries)
            except EvidenceError as exc:
                if p["status"] == "malformed" and p["failure"] == str(exc) and p["candidate_count"] is None and p["files"] == []:
                    return allowed_requests
                raise
            if actual_tree_sha != p["tree_sha"]:
                if p["status"] == "contradictory" and p["failure"] == "tree_content_hash_mismatch" and p["candidate_count"] is None and p["files"] == []:
                    return allowed_requests
                raise EvidenceError("tree_snapshot_content_hash_mismatch")
        membership = {}
        for entry in entries:
            if not isinstance(entry, dict) or not _safe_tree_path(entry.get("path")):
                raise EvidenceError("tree_path_invalid")
            path = entry["path"]
            if path in membership:
                raise EvidenceError("duplicate_tree_path")
            membership[path] = entry
        expected_candidates = {
            path: entry["sha"] for path, entry in membership.items()
            if entry.get("type") == "blob" and entry.get("mode") in ("100644", "100755") and _is_metadata_path(path)
        }
        allowed_requests.update(f"{base}/git/blobs/{sha}" for sha in expected_candidates.values())
        if p["candidate_count"] != len(expected_candidates):
            raise EvidenceError("candidate_count_mismatch")
        if type(p["candidate_count"]) is not int:
            raise EvidenceError("candidate_count_type_invalid")
        if p["status"] == "complete" and tree_doc.get("truncated") is not False:
            raise EvidenceError("complete_tree_not_complete")
    elif p["status"] == "complete":
        raise EvidenceError("complete_project_missing_tree_snapshot")
    seen = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise EvidenceError("file_record_invalid")
        path = item["path"]
        if not _safe_tree_path(path) or path in seen:
            raise EvidenceError("unsafe_or_duplicate_source_path")
        seen.add(path)
        entry = (tree_doc and {e["path"]: e for e in tree_doc["tree"]}.get(path))
        if entry is None or entry.get("type") != "blob" or entry.get("mode") not in ("100644", "100755"):
            raise EvidenceError("file_not_in_authenticated_tree_snapshot")
        if entry.get("sha") != item.get("blob_sha") or not _is_metadata_path(path):
            raise EvidenceError("file_tree_membership_mismatch")
        if "raw_base64" not in item:
            if set(item) != {"path", "blob_sha", "status"} or not isinstance(item["status"], str):
                raise EvidenceError("unavailable_file_schema_invalid")
            continue
        expected_file_keys = {"path", "blob_sha", "request_url", "sha256", "bytes", "raw_base64", "parsed"}
        _exact_keys(item, expected_file_keys, "file")
        expected_url = f"{API_ORIGIN}/repos/{p['repository']}/git/blobs/{entry['sha']}"
        if item["request_url"] != expected_url:
            raise EvidenceError("blob_request_url_mismatch")
        raw = base64.b64decode(item["raw_base64"], validate=True)
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise EvidenceError("source_content_sha256_mismatch")
        if _git_blob_sha(raw) != entry["sha"]:
            raise EvidenceError("source_content_not_tree_blob")
        if item["parsed"] != parse_metadata(path, raw):
            raise EvidenceError("parsed_metadata_not_recomputed_from_source")
    if p["status"] == "complete":
        if p["failure"] is not None or p["tree_truncated"] is not False:
            raise EvidenceError("complete_project_has_failure_or_truncated_tree")
        expected_paths = {path for path in expected_candidates}
        if seen != expected_paths or any("raw_base64" not in f for f in files):
            raise EvidenceError("complete_project_source_coverage_mismatch")
    elif p["status"] == "truncated":
        if p["failure"] not in {"tree_api_truncated", "metadata_file_cap_exceeded", "response_truncated_or_byte_budget_exhausted", "response_truncated"}:
            raise EvidenceError("truncated_project_reason_invalid")
    elif p["status"] == "unavailable" and not isinstance(p["failure"], str):
        raise EvidenceError("unavailable_project_reason_missing")
    elif p["status"] == "incomplete" and not isinstance(p["failure"], str):
        raise EvidenceError("incomplete_project_reason_missing")
    if tree_doc is None and p["tree_evidence"] is None:
        if p["tree_truncated"] is not None or p["candidate_count"] is not None or files:
            raise EvidenceError("project_without_tree_has_tree_data")
        if p["tree_sha"] is not None and (commit_doc is None or p["tree_sha"] != commit_doc.get("commit", {}).get("tree", {}).get("sha")):
            raise EvidenceError("unfetched_tree_sha_not_bound_to_commit")
        if p["status"] not in {"unavailable", "malformed", "contradictory"} and not (p["status"] == "truncated" and p["failure"] in {"response_truncated_or_byte_budget_exhausted", "response_truncated"}):
            raise EvidenceError("project_without_tree_must_be_unavailable")
    if tree_doc is None and p["tree_evidence"] is not None and p["status"] not in {"malformed", "contradictory"}:
        raise EvidenceError("unparsed_tree_requires_explicit_terminal_status")
    if p["status"] == "truncated" and p["failure"] == "metadata_file_cap_exceeded":
        if p["candidate_count"] is None or p["candidate_count"] <= MAX_FILES_PER_PROJECT:
            raise EvidenceError("file_cap_status_without_overflow")
        selected = {
            path for path, _ in sorted(expected_candidates.items(), key=lambda pair: _candidate_priority(pair[0]))[:MAX_FILES_PER_PROJECT]
        }
        if seen != selected or len(files) != MAX_FILES_PER_PROJECT:
            raise EvidenceError("file_cap_selection_mismatch")
    if p["status"] == "incomplete" and p["candidate_count"] is not None and p["candidate_count"] <= MAX_FILES_PER_PROJECT:
        if seen != set(expected_candidates):
            raise EvidenceError("incomplete_source_coverage_not_explicit")
    return allowed_requests


def validate(payload: dict[str, Any], raw_payload: bytes | None = None) -> None:
    if raw_payload is not None and decode_json(raw_payload) != payload:
        raise EvidenceError("payload_parse_mismatch")
    required = {"schema_version", "protocol", "frozen_manifest_hashes", "collector_sha256", "integrity_basis", "collection", "projects"}
    _exact_keys(payload, required, "payload")
    if payload["schema_version"] != 3 or payload["protocol"] != "gh103-source-metadata-v3":
        raise EvidenceError("unsupported_protocol_version")
    if payload["integrity_basis"] != "raw GitHub REST response snapshots over HTTPS to api.github.com; Git tree and blob object IDs are recomputed; commit identity is checked against the frozen SHA and relies on GitHub/TLS as external authority; no independent signature is claimed":
        raise EvidenceError("integrity_basis_invalid")
    expected_projects, expected_hashes = population()
    if payload["frozen_manifest_hashes"] != expected_hashes:
        raise EvidenceError("frozen_manifest_hashes_mismatch")
    if not isinstance(payload["collector_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", payload["collector_sha256"]):
        raise EvidenceError("collector_hash_invalid")
    current_collector_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    historical_collector_sha256 = {
        3: "dfad140689521644a893373a719c9b2a9ec2b9c005dc7873e8e586a54bc60f18",
    }
    if payload["collector_sha256"] not in {current_collector_sha256, historical_collector_sha256[payload["schema_version"]]}:
        raise EvidenceError("collector_source_hash_mismatch")
    collection = _exact_keys(payload["collection"], {"requests", "response_bytes", "objects", "retries", "wall_seconds", "auth_source", "interpretation", "request_log"}, "collection")
    for key in ("requests", "response_bytes", "objects", "retries"):
        if type(collection[key]) is not int or collection[key] < 0:
            raise EvidenceError("collection_counter_invalid")
    if collection["requests"] > MAX_REQUESTS or collection["response_bytes"] > MAX_BYTES or collection["objects"] > MAX_OBJECTS or collection["retries"] > collection["requests"] or collection["objects"] > collection["requests"]:
        raise EvidenceError("collection_budget_exceeded")
    request_log = collection["request_log"]
    if not isinstance(request_log, list) or len(request_log) != collection["requests"]:
        raise EvidenceError("request_log_count_mismatch")
    if sum(r.get("bytes", -1) for r in request_log if isinstance(r, dict)) != collection["response_bytes"]:
        raise EvidenceError("request_log_byte_count_mismatch")
    if sum(1 for r in request_log if isinstance(r, dict) and r.get("status") == "success") != collection["objects"]:
        raise EvidenceError("request_log_object_count_mismatch")
    if sum(1 for r in request_log if isinstance(r, dict) and type(r.get("attempt")) is int and r["attempt"] > 1) != collection["retries"]:
        raise EvidenceError("request_log_retry_count_mismatch")
    prior_attempt: dict[str, int] = {}
    retryable_statuses = {"truncated", "network_unavailable", "http_429", "http_500", "http_502", "http_503", "http_504"}
    prior_status: dict[str, str] = {}
    for request in request_log:
        _exact_keys(request, {"url", "attempt", "status", "bytes"}, "request")
        parsed_url = urllib.parse.urlsplit(request["url"])
        if parsed_url.scheme != "https" or parsed_url.netloc != "api.github.com" or not parsed_url.path.startswith("/repos/") or parsed_url.fragment:
            raise EvidenceError("request_log_origin_invalid")
        if type(request["attempt"]) is not int or request["attempt"] != prior_attempt.get(request["url"], 0) + 1 or request["attempt"] > RETRIES + 1:
            raise EvidenceError("request_log_attempt_invalid")
        if request["attempt"] > 1 and prior_status.get(request["url"]) not in retryable_statuses:
            raise EvidenceError("request_log_retry_after_nonretryable_status")
        prior_attempt[request["url"]] = request["attempt"]
        if request["status"] not in {"success", "truncated", "network_unavailable"} and not re.fullmatch(r"http_[1-5][0-9]{2}", request["status"]):
            raise EvidenceError("request_log_status_invalid")
        if type(request["bytes"]) is not int or request["bytes"] < 0:
            raise EvidenceError("request_log_bytes_invalid")
        if request["status"].startswith("http_"):
            response_limit = 4096
        elif request["status"] == "network_unavailable":
            response_limit = 0
        elif "/git/trees/" in parsed_url.path:
            response_limit = 8 * 1024 * 1024
        elif "/git/blobs/" in parsed_url.path:
            response_limit = MAX_BLOB_RESPONSE
        else:
            response_limit = 2 * 1024 * 1024
        if request["bytes"] > response_limit:
            raise EvidenceError("request_response_limit_exceeded")
        prior_status[request["url"]] = request["status"]
    if type(collection["wall_seconds"]) not in (int, float) or not 0 <= collection["wall_seconds"] <= MAX_WALL:
        raise EvidenceError("collection_wall_time_invalid")
    if collection["auth_source"] not in {"GITHUB_TOKEN", "gh_auth_profile", "unauthenticated"}:
        raise EvidenceError("auth_source_invalid")
    if collection["interpretation"] != "source metadata only; no compatibility or install/runtime feasibility proved":
        raise EvidenceError("interpretation_invalid")
    projects = payload["projects"]
    if not isinstance(projects, list) or len(projects) != 50:
        raise EvidenceError("exactly_50_projects_required")
    allowed_requests: set[str] = set()
    for project, expected in zip(projects, expected_projects, strict=True):
        allowed_requests.update(_validate_project(project, expected))
    successful: dict[str, list[int]] = {}
    for request in request_log:
        if request["url"] not in allowed_requests:
            raise EvidenceError("request_not_contained_in_frozen_source_snapshot")
        if request["status"] == "success":
            successful.setdefault(request["url"], []).append(request["bytes"])
    for project in projects:
        for snapshot in (project["commit_evidence"], project["tree_evidence"]):
            if snapshot is not None and snapshot["bytes"] not in successful.get(snapshot["request_url"], []):
                raise EvidenceError("snapshot_not_bound_to_successful_request")
        for item in project["files"]:
            if "raw_base64" in item and item["request_url"] not in successful:
                raise EvidenceError("source_blob_not_bound_to_successful_request")
    logged_bytes = sum(request["bytes"] for request in request_log)
    if logged_bytes != collection["response_bytes"]:
        raise EvidenceError("aggregate_response_byte_count_mismatch")
    evidence_object_urls: set[str] = set()
    for project in projects:
        for snapshot in (project["commit_evidence"], project["tree_evidence"]):
            if snapshot is not None:
                evidence_object_urls.add(snapshot["request_url"])
        evidence_object_urls.update(item["request_url"] for item in project["files"] if "raw_base64" in item)
    if len(evidence_object_urls) > collection["objects"]:
        raise EvidenceError("evidence_object_count_exceeds_successful_fetches")


def publish(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    if len(data) > MAX_RESULT_BYTES:
        raise EvidenceError("output_result_too_large")
    tmp = path.with_name(path.name + ".tmp")
    if path.exists() or tmp.exists():
        raise EvidenceError("no_clobber_target_exists")
    with tmp.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.link(tmp, path)
    except FileExistsError:
        raise EvidenceError("no_clobber_publication_race") from None
    finally:
        tmp.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--output", type=Path, default=OUT / "source-metadata-v3.json")
    args = parser.parse_args()
    try:
        if args.validate:
            payload, raw = load_json(args.validate)
            validate(payload, raw)
            print(f"valid: 50 projects; sha256:{hashlib.sha256(raw).hexdigest()}")
        elif args.collect:
            projects, hashes = population()
            token, auth_source = get_auth_token()
            client = Client(token)
            records = [collect_project(client, project) for project in projects]
            payload = {
                "schema_version": 3,
                "protocol": "gh103-source-metadata-v3",
                "frozen_manifest_hashes": hashes,
                "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "integrity_basis": INTEGRITY_BASIS,
                "collection": {
                    "requests": client.requests,
                    "response_bytes": client.response_bytes,
                    "objects": client.objects,
                    "retries": client.retries,
                    "request_log": client.request_log,
                    "wall_seconds": round(time.monotonic() - client.started, 3),
                    "auth_source": auth_source,
                    "interpretation": "source metadata only; no compatibility or install/runtime feasibility proved",
                },
                "projects": records,
            }
            validate(payload)
            publish(payload, args.output)
            complete = sum(p["status"] == "complete" for p in records)
            print(f"published {args.output}; {complete}/50 complete; sha256:{hashlib.sha256(args.output.read_bytes()).hexdigest()}")
        else:
            parser.error("choose --collect or --validate")
        return 0
    except (EvidenceError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
