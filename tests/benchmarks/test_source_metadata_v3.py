import base64
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "benchmarks/real_world"))
import source_metadata_v3 as sm


def _snapshot(url, raw):
    return {"request_url": url, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_base64": base64.b64encode(raw).decode()}


def sample_payload():
    projects, hashes = sm.population()
    return {
        "schema_version": 3, "protocol": "gh103-source-metadata-v3",
        "frozen_manifest_hashes": hashes,
        "collector_sha256": hashlib.sha256(Path(sm.__file__).read_bytes()).hexdigest(),
        "integrity_basis": "raw GitHub REST response snapshots over HTTPS to api.github.com; Git tree and blob object IDs are recomputed; commit identity is checked against the frozen SHA and relies on GitHub/TLS as external authority; no independent signature is claimed",
        "collection": {"requests": 0, "response_bytes": 0, "objects": 0, "retries": 0,
                       "wall_seconds": 0.0, "auth_source": "unauthenticated", "request_log": [],
                       "interpretation": "source metadata only; no compatibility or install/runtime feasibility proved"},
        "projects": [{"repository": p["repository"], "survey_commit": p["survey_commit"],
                      "status": "unavailable", "failure": "fixture_unavailable", "commit_evidence": None,
                      "tree_evidence": None, "tree_sha": None, "tree_truncated": None,
                      "candidate_count": None, "candidate_limit": sm.MAX_FILES_PER_PROJECT, "files": []}
                     for p in projects],
    }


def make_complete_project(payload, index=0, path="pyproject.toml", source=b"[project]\nrequires-python='>=3.11'\n"):
    project = payload["projects"][index]
    repo, commit = project["repository"], project["survey_commit"]
    blob_sha = sm._git_blob_sha(source)
    entry = {"path": path, "mode": "100644", "type": "blob", "sha": blob_sha, "size": len(source)}
    tree_sha = sm._git_tree_sha([entry])
    commit_doc = {"sha": commit, "commit": {"tree": {"sha": tree_sha}}}
    tree_doc = {"sha": tree_sha, "truncated": False, "tree": [entry]}
    commit_raw = json.dumps(commit_doc, separators=(",", ":")).encode()
    tree_raw = json.dumps(tree_doc, separators=(",", ":")).encode()
    blob_doc = {"sha": blob_sha, "encoding": "base64", "content": base64.b64encode(source).decode()}
    blob_api_raw = json.dumps(blob_doc, separators=(",", ":")).encode()
    base = "https://api.github.com/repos/" + repo
    item = {"path": path, "blob_sha": blob_sha, "request_url": base + "/git/blobs/" + blob_sha,
            "sha256": hashlib.sha256(source).hexdigest(), "bytes": len(source),
            "raw_base64": base64.b64encode(source).decode(), "parsed": sm.parse_metadata(path, source)}
    project.update(status="complete", failure=None,
                   commit_evidence=_snapshot(base + "/commits/" + commit, commit_raw),
                   tree_evidence=_snapshot(base + "/git/trees/" + tree_sha + "?recursive=1", tree_raw),
                   tree_sha=tree_sha, tree_truncated=False, candidate_count=1, files=[item])
    requests = [(base + "/commits/" + commit, commit_raw),
                (base + "/git/trees/" + tree_sha + "?recursive=1", tree_raw),
                (base + "/git/blobs/" + blob_sha, blob_api_raw)]
    payload["collection"].update(
        requests=3, response_bytes=sum(len(raw) for _, raw in requests), objects=3,
        request_log=[{"url": url, "attempt": 1, "status": "success", "bytes": len(raw)} for url, raw in requests],
    )
    return project


def test_valid_complete_project_binds_commit_tree_path_blob_and_parser():
    payload = sample_payload()
    make_complete_project(payload)
    sm.validate(payload)


def test_resealed_blob_not_in_tree_is_rejected():
    payload = sample_payload()
    make_complete_project(payload)
    item = payload["projects"][0]["files"][0]
    forged = b"[project]\nrequires-python='>=99.0'\n"
    sha = sm._git_blob_sha(forged)
    item.update(blob_sha=sha, request_url="https://api.github.com/repos/" + payload["projects"][0]["repository"] + "/git/blobs/" + sha,
                sha256=hashlib.sha256(forged).hexdigest(), bytes=len(forged), raw_base64=base64.b64encode(forged).decode(),
                parsed=sm.parse_metadata(item["path"], forged))
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)


def test_forged_commit_tree_link_and_tree_sha_are_rejected():
    payload = sample_payload()
    make_complete_project(payload)
    project = payload["projects"][0]
    project["tree_sha"] = "0" * 40
    commit_raw = json.dumps({"sha": project["survey_commit"], "commit": {"tree": {"sha": "0" * 40}}}).encode()
    project["commit_evidence"].update(raw_base64=base64.b64encode(commit_raw).decode(), bytes=len(commit_raw), sha256=hashlib.sha256(commit_raw).hexdigest())
    project["tree_evidence"]["request_url"] = "https://api.github.com/repos/" + project["repository"] + "/git/trees/" + "0" * 40 + "?recursive=1"
    tree_raw = json.dumps({"sha": "0" * 40, "truncated": False, "tree": []}).encode()
    project["tree_evidence"].update(raw_base64=base64.b64encode(tree_raw).decode(), bytes=len(tree_raw), sha256=hashlib.sha256(tree_raw).hexdigest())
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)


def test_parsed_fields_are_recomputed_from_raw_bytes():
    payload = sample_payload()
    make_complete_project(payload)
    payload["projects"][0]["files"][0]["parsed"]["requires_python"] = ">=99.0"
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)


def test_truncated_tree_and_file_failure_cannot_be_complete():
    payload = sample_payload()
    project = make_complete_project(payload)
    project["tree_truncated"] = True
    tree_doc = json.loads(base64.b64decode(project["tree_evidence"]["raw_base64"]))
    tree_doc["truncated"] = True
    tree_raw = json.dumps(tree_doc, separators=(",", ":")).encode()
    project["tree_evidence"].update(raw_base64=base64.b64encode(tree_raw).decode(), bytes=len(tree_raw), sha256=hashlib.sha256(tree_raw).hexdigest())
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)
    payload = sample_payload()
    project = make_complete_project(payload)
    blob_url = project["files"][0]["request_url"]
    project["files"] = [{"path": "pyproject.toml", "blob_sha": project["files"][0]["blob_sha"], "status": "http_403"}]
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)
    project["status"] = "incomplete"
    project["failure"] = "one_or_more_metadata_files_unavailable"
    log = payload["collection"]["request_log"]
    payload["collection"].update(
        response_bytes=sum(record["bytes"] for record in log[:2]), objects=2,
        request_log=log[:2] + [{"url": blob_url, "attempt": 1, "status": "http_403", "bytes": 0}],
    )
    sm.validate(payload)


def test_metadata_file_cap_is_explicitly_truncated():
    payload = sample_payload()
    project = payload["projects"][0]
    repo, commit = project["repository"], project["survey_commit"]
    entries = [{"path": "requirements-" + str(i) + ".txt", "mode": "100644", "type": "blob",
                "sha": sm._git_blob_sha(str(i).encode()), "size": 1} for i in range(sm.MAX_FILES_PER_PROJECT + 1)]
    tree_sha = sm._git_tree_sha(entries)
    commit_raw = json.dumps({"sha": commit, "commit": {"tree": {"sha": tree_sha}}}).encode()
    tree_raw = json.dumps({"sha": tree_sha, "truncated": False, "tree": entries}).encode()
    base = "https://api.github.com/repos/" + repo
    project.update(status="truncated", failure="metadata_file_cap_exceeded",
                   commit_evidence=_snapshot(base + "/commits/" + commit, commit_raw),
                   tree_evidence=_snapshot(base + "/git/trees/" + tree_sha + "?recursive=1", tree_raw),
                   tree_sha=tree_sha, tree_truncated=False, candidate_count=len(entries), files=[])
    requests = [(base + "/commits/" + commit, commit_raw),
                (base + "/git/trees/" + tree_sha + "?recursive=1", tree_raw)]
    files = []
    selected = sorted(entries, key=lambda item: sm._candidate_priority(item["path"]))[:sm.MAX_FILES_PER_PROJECT]
    for entry in selected:
        source = entry["path"].removeprefix("requirements-").removesuffix(".txt").encode()
        blob_sha = entry["sha"]
        blob_url = base + "/git/blobs/" + blob_sha
        blob_raw = json.dumps({"sha": blob_sha, "encoding": "base64", "content": base64.b64encode(source).decode()}, separators=(",", ":")).encode()
        files.append({"path": entry["path"], "blob_sha": blob_sha, "request_url": blob_url,
                      "sha256": hashlib.sha256(source).hexdigest(), "bytes": len(source),
                      "raw_base64": base64.b64encode(source).decode(), "parsed": sm.parse_metadata(entry["path"], source)})
        requests.append((blob_url, blob_raw))
    project["files"] = files
    payload["collection"].update(
        requests=len(requests), response_bytes=sum(len(raw) for _, raw in requests), objects=len(requests),
        request_log=[{"url": url, "attempt": 1, "status": "success", "bytes": len(raw)} for url, raw in requests],
    )
    sm.validate(payload)


def test_symlink_license_is_not_read_as_a_regular_source_file():
    payload = sample_payload()
    project = payload["projects"][0]
    repo, commit = project["repository"], project["survey_commit"]
    entry = {"path": "LICENSE", "mode": "120000", "type": "blob", "sha": sm._git_blob_sha(b"target"), "size": 6}
    tree_sha = sm._git_tree_sha([entry])
    commit_raw = json.dumps({"sha": commit, "commit": {"tree": {"sha": tree_sha}}}).encode()
    tree_raw = json.dumps({"sha": tree_sha, "truncated": False, "tree": [entry]}).encode()
    base = "https://api.github.com/repos/" + repo
    project.update(status="complete", failure=None,
                   commit_evidence=_snapshot(base + "/commits/" + commit, commit_raw),
                   tree_evidence=_snapshot(base + "/git/trees/" + tree_sha + "?recursive=1", tree_raw),
                   tree_sha=tree_sha, tree_truncated=False, candidate_count=0, files=[])
    requests = [(base + "/commits/" + commit, commit_raw),
                (base + "/git/trees/" + tree_sha + "?recursive=1", tree_raw)]
    payload["collection"].update(
        requests=2, response_bytes=sum(len(raw) for _, raw in requests), objects=2,
        request_log=[{"url": url, "attempt": 1, "status": "success", "bytes": len(raw)} for url, raw in requests],
    )
    sm.validate(payload)


def test_exact_population_and_strict_payload_schema():
    payload = sample_payload()
    sm.validate(payload)
    payload["projects"].pop()
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)
    payload = sample_payload()
    payload["collector_sha256"] = "0" * 64
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)
    payload = sample_payload()
    payload["unexpected"] = True
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)


def test_toml_pipfile_and_ini_extras_are_parsed_as_declarations():
    pipfile = sm.parse_metadata("Pipfile", b"[requires]\npython_version='3.11'\n[packages]\nhttpx='*'\n")
    assert pipfile["requires_python"] == "3.11"
    parsed = sm.parse_metadata("setup.cfg", b"[options]\npython_requires = >=3.9\n[options.extras_require]\ntest =\n    pytest\n    coverage\n")
    assert parsed["declared_fields"]["extras_require"] == {"test": ["pytest", "coverage"]}


def test_py310_toml_parser_absence_is_not_malformed(monkeypatch):
    monkeypatch.setattr(sm, "tomllib", None)
    parsed = sm.parse_metadata("pyproject.toml", b"[project]\nrequires-python='>=3.9'\n")
    assert parsed["status"] == "parser_unavailable"


def test_workflow_matrix_statuses_distinguish_absent_dynamic_and_static():
    path = ".github/workflows/test.yml"
    assert sm.parse_metadata(path, b"jobs:\n  test:\n    runs-on: ubuntu-latest\n")["status"] == "not_declared"
    dynamic = sm.parse_metadata(path, b"python-version: $" + b"{{ matrix.python-version }}\n")
    assert dynamic["status"] == "dynamic_expression"
    versions = sm.parse_metadata(path, b"strategy:\n  matrix:\n    python-version: [3.10, 3.11]\n")
    assert versions["python_versions"] == ["3.10", "3.11"]


def test_python_source_is_never_executed(tmp_path):
    marker = tmp_path / "executed"
    source = ("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('bad')\n"
              "setup(python_requires='>=3.10')\n").encode()
    sm.parse_metadata("setup.py", source)
    assert not marker.exists()


def test_duplicate_nonfinite_json_and_bad_budgets_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"x":1,"x":2}')
    with pytest.raises(sm.EvidenceError):
        sm.load_json(path)
    path.write_text('{"x":NaN}')
    with pytest.raises(sm.EvidenceError):
        sm.load_json(path)
    payload = sample_payload()
    payload["collection"]["requests"] = sm.MAX_REQUESTS + 1
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)
    payload = sample_payload()
    payload["collection"]["wall_seconds"] = sm.MAX_WALL + 1
    with pytest.raises(sm.EvidenceError):
        sm.validate(payload)


def test_client_retries_cannot_exceed_request_budget(monkeypatch):
    client = sm.Client(None)
    client.requests = sm.MAX_REQUESTS - 1

    class AlwaysFail:
        def open(self, *args, **kwargs):
            raise sm.urllib.error.HTTPError("https://api.github.com", 503, "", {}, None)

    monkeypatch.setattr(sm.urllib.request, "build_opener", lambda *_: AlwaysFail())
    with pytest.raises(sm.EvidenceError):
        client.get("https://api.github.com/repos/a/b/commits/" + "a" * 40, 1024)
    assert client.requests <= sm.MAX_REQUESTS


def test_source_paths_are_canonical_and_no_clobber(tmp_path):
    for bad in ("../x", "/x", "a\\b", "a//b", "./a"):
        assert not sm._safe_tree_path(bad)
    dest = tmp_path / "result.json"
    sm.publish({"ok": True}, dest)
    with pytest.raises(sm.EvidenceError):
        sm.publish({"ok": False}, dest)
