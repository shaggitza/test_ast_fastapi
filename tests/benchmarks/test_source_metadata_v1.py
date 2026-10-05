import base64
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "benchmarks/real_world"))
import source_metadata_v1 as sm


def sample():
    projects, hashes = sm.population()
    return {"schema_version": 1, "frozen_manifest_hashes": hashes,
            "projects": [{**p, "commit_status": "unavailable_or_unverified", "retrieval_status": "fixture_unavailable", "files": []} for p in projects]}


def test_literal_setup_metadata_is_parsed_as_data():
    raw = b"from setuptools import setup\nsetup(python_requires='>=3.10', install_requires=['fastapi>=0.1'])\n"
    parsed = sm.parse_metadata("setup.py", raw)
    assert parsed["status"] == "parsed"
    assert parsed["declared_fields"] == {"python_requires": ">=3.10", "install_requires": ["fastapi>=0.1"]}
    # The setup call is parsed as AST data and never evaluated.


def test_pyproject_declared_constraints_are_not_runtime_claims():
    parsed = sm.parse_metadata("pyproject.toml", b"[project]\nrequires-python='>=3.9'\ndependencies=['httpx']\n")
    assert parsed["requires_python"] == ">=3.9"
    assert parsed["dependencies"] == ["httpx"]


def test_exact_fifty_and_hash_validation():
    payload = sample()
    sm.validate(payload)
    payload["projects"].pop()
    with pytest.raises(sm.EvidenceError): sm.validate(payload)


def test_missing_and_tampered_raw_evidence_fail():
    payload = sample()
    f = b"[project]\nrequires-python='>=3.11'\n"
    blob_sha = hashlib.sha1(b"blob " + str(len(f)).encode() + b"\0" + f).hexdigest()
    payload["projects"][0]["files"] = [{"path": "pyproject.toml", "blob_sha": blob_sha, "request_url": f"https://api.github.com/repos/{payload['projects'][0]['repository']}/git/blobs/{blob_sha}", "bytes": len(f), "sha256": hashlib.sha256(f).hexdigest(), "raw_base64": base64.b64encode(f).decode(), "parsed": {"sha256": hashlib.sha256(f).hexdigest()}}]
    sm.validate(payload)
    payload["projects"][0]["files"][0]["raw_base64"] = base64.b64encode(f + b"x").decode()
    with pytest.raises(sm.EvidenceError): sm.validate(payload)
    payload = sample(); payload["projects"][0]["files"] = [{"path": "../escape", "status": "unavailable"}]
    with pytest.raises(sm.EvidenceError): sm.validate(payload)


def test_duplicate_json_keys_and_nonfinite_rejected(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"x":1,"x":2}')
    with pytest.raises(sm.EvidenceError): sm.load_json(p)
    p.write_text('{"x":NaN}')
    with pytest.raises(sm.EvidenceError): sm.load_json(p)


def test_no_clobber(tmp_path):
    path = tmp_path / "result.json"
    sm.publish({"ok": True}, path)
    with pytest.raises(sm.EvidenceError): sm.publish({"ok": False}, path)
