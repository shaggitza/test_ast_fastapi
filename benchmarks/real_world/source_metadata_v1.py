#!/usr/bin/env python3
"""Bounded, read-only source metadata evidence at frozen GH103 survey commits.

Upstream content is fetched and parsed as data only; nothing is imported or run.
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import re
import configparser
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EXP = ROOT / "benchmarks/real_world/expansion"
OUT = ROOT / "benchmarks/results/gh103-source-metadata-v1"
V1_HASH = "194afecc671535639cf51b4b98e6fbe2d36a6159c882de1ae2bd3a4df1a28fe0"
V2_HASH = "abd4ee6418a70bf1963a379b26d3ddaf1fe43b2a5a5b60f4090801d1ac5dbc1c"
MAX_REQUESTS, MAX_BYTES, MAX_FILES, MAX_FILE = 500, 32 * 1024 * 1024, 600, 512 * 1024
MAX_WALL, TIMEOUT, RETRIES = 900, 15, 2
METADATA_NAMES = {"pyproject.toml", "setup.cfg", "setup.py", "tox.ini", "Pipfile"}
LICENSE_NAMES = {"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt", "LICENSE.rst"}


class EvidenceError(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise EvidenceError(f"duplicate JSON key: {k}")
        result[k] = v
    return result


def _constant(value):
    raise EvidenceError(f"non-finite JSON number: {value}")


def load_json(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant), raw


def population() -> tuple[list[dict[str, str]], dict[str, str]]:
    m1, b1 = load_json(EXP / "projects-50-v1.json")
    m2, b2 = load_json(EXP / "projects-50x50-v2.json")
    if hashlib.sha256(b1).hexdigest() != V1_HASH or hashlib.sha256(b2).hexdigest() != V2_HASH:
        raise EvidenceError("frozen population manifest hash mismatch")
    a = {p["repository"]: p["survey_commit"] for p in m1["projects"]}
    b = {p["repository"]: p["survey_commit"] for p in m2["projects"]}
    if len(a) != 50 or a != b:
        raise EvidenceError("frozen population mismatch; expected exact 50 survey commits")
    return [{"repository": r, "survey_commit": c} for r, c in b.items()], {
        "v1": "sha256:" + V1_HASH, "v2": "sha256:" + V2_HASH,
    }


class Client:
    def __init__(self, token: str | None):
        self.token = token
        self.started = time.monotonic()
        self.requests = self.bytes = self.files = 0

    def get(self, url: str, limit: int = MAX_FILE) -> bytes:
        if not url.startswith("https://api.github.com/"):
            raise EvidenceError("request host rejected")
        if self.requests >= MAX_REQUESTS or self.files >= MAX_FILES or time.monotonic() - self.started > MAX_WALL:
            raise EvidenceError("collection budget exhausted")
        for attempt in range(RETRIES + 1):
            req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "GH103-source-metadata/1"})
            if self.token:
                req.add_header("Authorization", "Bearer " + self.token)
            self.requests += 1
            try:
                # urllib's default redirect handler is disabled: never forward credentials.
                with urllib.request.build_opener(_NoRedirect()).open(req, timeout=TIMEOUT) as response:
                    raw = response.read(limit + 1)
                if len(raw) > limit:
                    raise EvidenceError("response truncated at configured byte bound")
                self.bytes += len(raw)
                if self.bytes > MAX_BYTES:
                    raise EvidenceError("aggregate byte budget exhausted")
                self.files += 1
                return raw
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    raise EvidenceError("redirect_rejected")
                if e.code == 429 or e.code >= 500:
                    if attempt < RETRIES:
                        time.sleep(min(2 ** attempt, 4)); continue
                raise EvidenceError(f"http_{e.code}") from None
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < RETRIES:
                    time.sleep(min(2 ** attempt, 4)); continue
                raise EvidenceError("network_unavailable") from None
        raise EvidenceError("retry_exhausted")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_metadata(path: str, raw: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        result.update(status="malformed", reason="not_utf8"); return result
    if path.endswith(".toml"):
        try:
            import tomllib
            doc = tomllib.loads(text)
            project = doc.get("project", {})
            result.update(status="parsed", requires_python=project.get("requires-python", "not_declared"), dependencies=project.get("dependencies", "not_declared"), optional_dependencies=project.get("optional-dependencies", "not_declared"))
        except Exception:
            result.update(status="malformed", reason="toml_parse_error")
    elif path.endswith(".cfg") or path == "tox.ini":
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(text)
            fields = {}
            for section, key in (("options", "python_requires"), ("options", "install_requires"), ("options", "extras_require"), ("metadata", "classifiers")):
                if parser.has_option(section, key): fields[key] = parser.get(section, key).strip().splitlines()
            result.update(status="parsed", declared_fields=fields)
        except configparser.Error:
            result.update(status="malformed", reason="ini_parse_error")
    else:
        try:
            tree = ast.parse(text, filename=path)
            fields = {}
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    call = node.value
                    if isinstance(call.func, ast.Name) and call.func.id == "setup":
                        for kw in call.keywords:
                            if kw.arg in {"python_requires", "install_requires", "extras_require", "classifiers", "license"}:
                                try: fields[kw.arg] = ast.literal_eval(kw.value)
                                except (ValueError, TypeError): fields[kw.arg] = "dynamic_or_nonliteral"
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name) and target.id in {"python_requires", "install_requires", "extras_require", "classifiers", "license"}:
                            try: fields[target.id] = ast.literal_eval(node.value)
                            except (ValueError, TypeError): fields[target.id] = "dynamic_or_nonliteral"
            result.update(status="parsed", declared_fields=fields)
        except (SyntaxError, ValueError):
            result.update(status="malformed", reason="python_ast_parse_error")
    return result


def collect_project(client: Client, project: dict[str, str]) -> dict[str, Any]:
    repo, commit = project["repository"], project["survey_commit"]
    base = "https://api.github.com/repos/" + repo
    try:
        commit_doc = json.loads(client.get(f"{base}/commits/{commit}", 2 * 1024 * 1024), object_pairs_hook=_pairs)
        if commit_doc.get("sha") != commit:
            raise EvidenceError("requested_commit_identity_mismatch")
        tree_sha = commit_doc["commit"]["tree"]["sha"]
        tree = json.loads(client.get(f"{base}/git/trees/{tree_sha}?recursive=1", 8 * 1024 * 1024), object_pairs_hook=_pairs)
        if tree.get("sha") != tree_sha:
            raise EvidenceError("requested_tree_identity_mismatch")
        selected = []
        for entry in tree.get("tree", []):
            p = entry.get("path", "")
            parts = PurePosixPath(p).parts
            if not p or p.startswith("/") or ".." in parts or entry.get("type") != "blob":
                continue
            name = parts[-1]
            if name in METADATA_NAMES or name in LICENSE_NAMES or (p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))):
                selected.append(entry)
        selected = selected[:12]
        files, aggregate = [], 0
        for ent in selected:
            p, sha = ent["path"], ent["sha"]
            try:
                blob = json.loads(client.get(f"{base}/git/blobs/{sha}", MAX_FILE + 1024), object_pairs_hook=_pairs)
                raw = base64.b64decode(blob["content"], validate=False)
                if blob.get("sha") != sha or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != sha:
                    raise EvidenceError("requested_blob_identity_mismatch")
                aggregate += len(raw)
                if len(raw) > MAX_FILE or aggregate > 2 * 1024 * 1024:
                    raise EvidenceError("project_file_budget_exceeded")
                item = {"path": p, "blob_sha": sha, "request_url": f"{base}/git/blobs/{sha}", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "raw_base64": base64.b64encode(raw).decode("ascii")}
                if PurePosixPath(p).name in METADATA_NAMES:
                    item["parsed"] = parse_metadata(p, raw)
                elif p.startswith(".github/workflows/"):
                    text = raw.decode("utf-8", errors="replace")
                    versions = sorted(set(re.findall(r"(?:python-version|python_version)\s*:\s*['\"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?|['\"][0-9. ,\[\]-]+['\"])", text)))
                    item["parsed"] = {"status": "parsed_declaration" if versions else "no_declaration_observed", "python_version_matrix_literals": versions, "note": "workflow declarations only; not evidence of successful runtime compatibility"}
                else:
                    item["parsed"] = {"status": "retrieved", "kind": "license_text"}
                files.append(item)
            except EvidenceError as e:
                files.append({"path": p, "blob_sha": sha, "status": str(e)})
        return {"repository": repo, "survey_commit": commit, "commit_request_url": f"{base}/commits/{commit}", "commit_status": "verified", "tree_request_url": f"{base}/git/trees/{tree_sha}?recursive=1", "tree_sha": tree_sha, "tree_status": "verified", "retrieval_status": "complete", "files": files}
    except Exception as e:
        return {"repository": repo, "survey_commit": commit, "commit_status": "unavailable_or_unverified", "retrieval_status": str(e)[:120], "files": []}


def validate(payload: dict[str, Any], raw_payload: bytes | None = None) -> None:
    if raw_payload is not None:
        parsed = json.loads(raw_payload, object_pairs_hook=_pairs, parse_constant=_constant)
        if parsed != payload:
            raise EvidenceError("payload parse mismatch")
    expected, hashes = population()
    if payload.get("schema_version") != 1 or payload.get("frozen_manifest_hashes") != hashes:
        raise EvidenceError("schema or frozen profile mismatch")
    projects = payload.get("projects")
    if not isinstance(projects, list) or len(projects) != 50:
        raise EvidenceError("exactly 50 project records required")
    if [(p.get("repository"), p.get("survey_commit")) for p in projects] != [(p["repository"], p["survey_commit"]) for p in expected]:
        raise EvidenceError("project coverage/order/commit mismatch")
    for project in projects:
        if project.get("retrieval_status") == "complete":
            repo, commit = project["repository"], project["survey_commit"]
            if project.get("commit_status") != "verified" or project.get("tree_status") != "verified":
                raise EvidenceError("complete project lacks verified source snapshot")
            if project.get("commit_request_url") != f"https://api.github.com/repos/{repo}/commits/{commit}":
                raise EvidenceError("commit request provenance mismatch")
            if project.get("tree_request_url") != f"https://api.github.com/repos/{repo}/git/trees/{project.get('tree_sha')}?recursive=1":
                raise EvidenceError("tree request provenance mismatch")
        elif project.get("retrieval_status") in (None, ""):
            raise EvidenceError("project lacks explicit retrieval status")
        seen = set()
        for f in project.get("files", []):
            path = f.get("path")
            parts = PurePosixPath(path or "").parts
            if not path or path.startswith("/") or ".." in parts or path in seen:
                raise EvidenceError("unsafe or duplicate source path")
            seen.add(path)
            if "raw_base64" in f:
                expected_url = f"https://api.github.com/repos/{project['repository']}/git/blobs/{f.get('blob_sha')}"
                if f.get("request_url") != expected_url:
                    raise EvidenceError("blob request provenance mismatch")
                raw = base64.b64decode(f["raw_base64"], validate=True)
                if len(raw) != f["bytes"] or hashlib.sha256(raw).hexdigest() != f["sha256"]:
                    raise EvidenceError("raw source hash/size mismatch")
                if hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != f["blob_sha"]:
                    raise EvidenceError("Git blob identity mismatch")
                if f.get("parsed", {}).get("sha256") not in (None, f["sha256"]):
                    raise EvidenceError("parsed provenance mismatch")
            elif f.get("status") is None:
                raise EvidenceError("file lacks explicit retrieval status")


def publish(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    tmp = path.with_name(path.name + ".tmp")
    if path.exists() or tmp.exists():
        raise EvidenceError("no-clobber publication target already exists")
    with tmp.open("xb") as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    try: os.link(tmp, path)
    except FileExistsError: raise EvidenceError("no-clobber publication race")
    finally: tmp.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate", type=Path)
    ap.add_argument("--collect", action="store_true")
    ap.add_argument("--output", type=Path, default=OUT / "source-metadata-v1.json")
    args = ap.parse_args()
    try:
        if args.validate:
            payload, raw = load_json(args.validate); validate(payload, raw)
            print(f"valid: 50 projects; sha256:{hashlib.sha256(raw).hexdigest()}")
        elif args.collect:
            projects, hashes = population()
            client = Client(os.environ.get("GITHUB_TOKEN"))
            records = [collect_project(client, p) for p in projects]
            payload = {"schema_version": 1, "protocol": "gh103-source-metadata-v1", "frozen_manifest_hashes": hashes,
                       "collection": {"collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "requests": client.requests, "response_bytes": client.bytes, "files_considered": client.files, "wall_seconds": round(time.monotonic()-client.started, 3), "token_present": bool(client.token), "interpretation": "source metadata only; no compatibility or install/runtime feasibility proved"}, "projects": records}
            validate(payload); publish(payload, args.output)
            print(f"published {args.output}; {sum(p['retrieval_status']=='complete' for p in records)}/50 complete; sha256:{hashlib.sha256(args.output.read_bytes()).hexdigest()}")
        else: ap.error("choose --collect or --validate")
        return 0
    except (EvidenceError, OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
