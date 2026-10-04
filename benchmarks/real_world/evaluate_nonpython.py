#!/usr/bin/env python3
"""Evaluate audited non-Python cases with the pinned finite client scanner.

Third-party snapshot files are read as text only. The scanner source is loaded
from the exact trusted internal PR #310 commit recorded below.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

SCANNER_COMMIT = "1d9242d0d1d411b529c3227918aa2d05e98e8943"
SCANNER_PATH = "src/fastapi_endpoint_detector/analyzer/client_observations.py"
HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "nonpython_v1"
WORKER = r"""
import json, sys
from pathlib import Path
from fastapi_endpoint_detector.analyzer.client_observations import (
    EstablishedSurface, extract_client_observations, join_established_surfaces,
)
payload=json.load(sys.stdin)
payload["source_root"]=Path(payload["source_root"])
out={}
for case in payload["cases"]:
    observations=[]
    for rel in case["client_files"]:
        p=payload["source_root"]/case["source_key"]/rel
        text=p.read_text(encoding="utf-8")
        observations.extend(extract_client_observations(text, rel))
    observations=tuple(observations)
    surfaces=tuple(EstablishedSurface(
        atom["surface_id"], atom["path"], atom["method"], None, True
    ) for atom in case["atoms"])
    joined=join_established_surfaces(observations, surfaces)
    out[case["case_id"]]={
       "observations":[{
          "source_path":str(o.source_path),"line":o.line,"protocol":o.protocol,
          "method":o.method,"literal_url":o.literal_url,"origin":o.origin,
          "raw_route_path":o.route_path,"query_evidence":o.query,
          "normalized_route_identity":f"{o.method} {o.route_path}",
          "start_offset":o.start_offset,"end_offset":o.end_offset,
       } for o in observations],
       "joined_surface_ids":[m.surface_id for m in joined],
    }
json.dump(out,sys.stdout,sort_keys=True)
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run() -> int:  # noqa: PLR0915
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", type=Path, default=FIXTURE / "results/evaluation.json")
    parser.add_argument("--scanner-commit", default=SCANNER_COMMIT)
    args = parser.parse_args()

    manifest = json.loads((FIXTURE / "source_manifest.json").read_text())
    spec = json.loads((FIXTURE / "evaluation_cases.json").read_text())
    root = FIXTURE / "source"

    verified_files: list[dict[str, object]] = []
    for key, case in manifest["cases"].items():
        for record in case["files"]:
            rel = Path(key) / record["path"]
            payload = (root / rel).read_bytes()
            actual = sha256(payload)
            if actual != record["sha256"]:
                raise SystemExit(f"source hash mismatch: {rel}: {actual}")
            verified_files.append(
                {"source_key": key, "path": record["path"], "sha256": actual, "bytes": len(payload)}
            )

    diff_records: list[dict[str, object]] = []
    for key, record in manifest.get("diffs", {}).items():
        payload = (FIXTURE / record["path"]).read_bytes()
        actual = sha256(payload)
        if actual != record["sha256"]:
            raise SystemExit(f"diff hash mismatch: {key}: {actual}")
        diff_records.append(
            {
                "case_id": key,
                "commit": record["commit"],
                "path": record["path"],
                "sha256": actual,
                "bytes": len(payload),
            }
        )

    repo_root = Path(__file__).resolve().parents[2]
    archive = subprocess.run(
        ["git", "archive", "--format=tar", args.scanner_commit],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    with tempfile.TemporaryDirectory(prefix="nonpython-pr310-") as temp:
        extracted = Path(temp)
        with tarfile.open(fileobj=__import__("io").BytesIO(archive), mode="r:") as tf:
            tf.extractall(extracted, filter="data")
        scanner_bytes = (extracted / SCANNER_PATH).read_bytes()
        env = os.environ.copy()
        env["PYTHONPATH"] = str(extracted / "src")
        source_keys = {
            "khoj-ai/khoj#1216": "khoj_1216",
            "khoj-ai/khoj#1221": "khoj_1221",
            "khoj-ai/khoj#1235": "khoj_1235",
            "open-webui/open-webui#26384": "openwebui_26384",
            "open-webui/open-webui#26405": "openwebui_26405",
        }
        cases = []
        for case in spec["cases"]:
            if case.get("mode") not in {"typescript_client", "svelte_client"}:
                continue
            item = dict(case)
            item["source_key"] = source_keys[case["case_id"]]
            cases.append(item)
        payload = {"cases": cases, "source_root": str(root)}
        proc = subprocess.run(
            [sys.executable, "-c", WORKER],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if proc.returncode:
            raise SystemExit(proc.stderr)
        scan = json.loads(proc.stdout)

    result_cases = []
    for case in spec["cases"]:
        record: dict[str, object] = {
            "case_id": case["case_id"],
            "merge_snapshot": case.get("merge_snapshot"),
            "audit": case.get("audit"),
            "audit_sha256": case.get("audit_sha256"),
            "mode": case.get("mode"),
            "status": case.get("status", "evaluated"),
            "reviewed_historical_atoms": case.get("atoms", []),
        }
        if case.get("mode") in {"typescript_client", "svelte_client"}:
            observation = scan[case["case_id"]]
            record["raw_normalized_observations"] = observation["observations"]
            record["explicit_established_surface_joins"] = observation["joined_surface_ids"]
            record["atom_comparison"] = [
                {
                    "reviewed_atom": f"{atom['method']} {atom['path']}",
                    "query_evidence": atom.get("query_evidence"),
                    "surface_id": atom["surface_id"],
                    "scanner_abstention": (
                        "origin_attestation_missing"
                        if any(
                            o["method"] == atom["method"] and o["raw_route_path"] == atom["path"]
                            for o in observation["observations"]
                        )
                        else "no_exact_literal_method_path_observation"
                    ),
                }
                for atom in case["atoms"]
            ]
            record["metric_note"] = (
                "Comparison to provisional reviewed historical atoms only; "
                "not canonical truth scoring."
            )
        elif case.get("mode") == "docker_env_subprocess":
            record["impact_classification"] = "conditional_deployment_impact"
            record["runtime_observed"] = False
            record["metric_note"] = (
                "Source contract retained conditionally; no runtime or image "
                "execution was performed."
            )
        result_cases.append(record)

    client_atoms = [
        a
        for c in spec["cases"]
        if c.get("mode") in {"typescript_client", "svelte_client"}
        for a in c["atoms"]
    ]
    client_joins = sum(len(scan[c["case_id"]]["joined_surface_ids"]) for c in cases)
    unresolved = [
        c for c in spec["cases"] if c.get("status") == "identity_and_immutable_inputs_not_located"
    ]
    result = {
        "schema": "nonpython-evaluation-results-v1",
        "evaluation_scope": (
            "6 audited PR cases with pinned source plus 3 unresolved expected slots"
        ),
        "truth_status": spec["truth_status"],
        "scanner": {
            "repository_commit": args.scanner_commit,
            "source_path": SCANNER_PATH,
            "source_sha256": sha256(scanner_bytes),
        },
        "source_manifest_sha256": sha256((FIXTURE / "source_manifest.json").read_bytes()),
        "protocol_evidence_sha256": sha256((FIXTURE / "protocol_evidence.json").read_bytes()),
        "verified_source_file_count": len(verified_files),
        "verified_source_files": verified_files,
        "verified_diff_count": len(diff_records),
        "verified_diffs": diff_records,
        "available_cases": 6,
        "unresolved_case_slots": len(unresolved),
        "client_reviewed_atom_count": len(client_atoms),
        "client_explicit_origin_gated_joins": client_joins,
        "client_nonjoined_reviewed_atoms": len(client_atoms) - client_joins,
        "evaluation_warning": (
            "Six available PR audits identify nine client/deployment route atoms. "
            "This does not establish the missing three PR identities or complete "
            "nine-case acceptance."
        ),
        "cases": result_cases,
    }
    args.write.parent.mkdir(parents=True, exist_ok=True)
    args.write.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "available_cases",
                    "unresolved_case_slots",
                    "client_reviewed_atom_count",
                    "client_explicit_origin_gated_joins",
                    "client_nonjoined_reviewed_atoms",
                    "scanner",
                )
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
