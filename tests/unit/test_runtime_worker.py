"""Protocol and bounded trusted-fixture tests for the VM runtime worker."""

from __future__ import annotations

import io
import json
import sys
from typing import TYPE_CHECKING

from pydantic import BaseModel

from fastapi_endpoint_detector.parser import runtime_worker

if TYPE_CHECKING:
    from pathlib import Path

_IMAGE = "registry.example/detector@sha256:" + "a" * 64


def _request(app: Path, *, phase: str = "list", diff: Path | None = None) -> str:
    return json.dumps(
        {
            "schema_version": 3,
            "phase": phase,
            "app_path": str(app),
            "app_variable": "app",
            "app_entry": "toy_api.factory:create_app",
            "bootstrap_entry": "toy_api.bootstrap:register_routes",
            "diff_path": str(diff) if diff is not None else None,
            "output_limit_bytes": 4 * 1024 * 1024,
            "dependency_max_depth": 10,
            "dependency_max_nodes": 4096,
            "dependency_max_work": 65536,
            "runtime_pins": {
                "runtime_image": _IMAGE,
                "runtime_image_digest": _IMAGE.split("@", maxsplit=1)[1],
                "dependency_lock_sha256": "sha256:" + "b" * 64,
                "snapshot_lock_sha256": "sha256:" + "c" * 64,
                "sbom_sha256": "sha256:" + "d" * 64,
                "seccomp_sha256": "sha256:" + "e" * 64,
                "runtime_policy_sha256": "sha256:" + "f" * 64,
            },
        }
    )


def _toy_project(root: Path) -> Path:
    package = root / "toy_api"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helper.py").write_text("PATH = '/selected-root'\n", encoding="utf-8")
    (package / "factory.py").write_text(
        "from fastapi import FastAPI\n"
        "def create_app():\n"
        "    from .helper import PATH\n"
        "    return FastAPI(title=PATH)\n",
        encoding="utf-8",
    )
    (package / "bootstrap.py").write_text(
        "def register_routes(app):\n"
        "    from .helper import PATH\n"
        "    @app.get(PATH)\n"
        "    def selected():\n"
        "        return {'selected': True}\n",
        encoding="utf-8",
    )
    return package


def test_worker_list_uses_exact_selected_factory_and_bootstrap(tmp_path: Path, monkeypatch) -> None:
    _toy_project(tmp_path)
    monkeypatch.setattr(runtime_worker, "_container_process_rss_bytes", lambda: None)
    payload, status = runtime_worker.run_request(_request(tmp_path, phase="list"))
    assert status == 0
    assert payload["status"] == "ok"
    assert payload["phase"] == "list"
    assert [item["path"] for item in payload["endpoints"]] == ["/selected-root"]
    assert payload["telemetry"] == {
        "container_peak_rss_bytes": None,
        "container_peak_rss_status": "unsupported",
        "source": None,
    }


def test_worker_requires_complete_exact_pins_and_bounded_config(tmp_path: Path) -> None:
    package = _toy_project(tmp_path)
    request = json.loads(_request(tmp_path))
    del request["runtime_pins"]["runtime_policy_sha256"]
    payload, status = runtime_worker.run_request(json.dumps(request))
    assert status == 1
    assert payload["status"] == "error"
    assert "complete immutable pin set" in payload["message"]

    request = json.loads(_request(tmp_path))
    request["dependency_max_depth"] = 65
    payload, status = runtime_worker.run_request(json.dumps(request))
    assert status == 1
    assert "dependency_max_depth" in payload["message"]
    assert package.is_dir()


def test_worker_stops_collecting_before_serialized_inventory_exceeds_limit(
    tmp_path: Path, monkeypatch
) -> None:
    yielded = 0
    dumped = 0

    class OversizedEndpoint(BaseModel):
        path: str

        def model_dump(self, *, mode: str) -> dict[str, str]:
            nonlocal dumped
            assert mode == "json"
            dumped += 1
            return super().model_dump(mode=mode)

    class FakeExtractor:
        def extract_endpoints(self):
            nonlocal yielded
            for _ in range(100):
                yielded += 1
                yield OversizedEndpoint(path="/" + "x" * 2048)

    monkeypatch.setattr(runtime_worker, "_extractor", lambda _request: FakeExtractor())
    monkeypatch.setattr(runtime_worker, "_container_process_rss_bytes", lambda: None)
    request = json.loads(_request(tmp_path))
    request["output_limit_bytes"] = 512

    payload, status = runtime_worker.run_request(json.dumps(request))

    assert status == 1
    assert payload["status"] == "error"
    assert "exceeded the serialized output limit" in payload["message"]
    assert yielded == 1
    assert dumped == 0


def test_v3_unicode_nested_error_response_respects_utf8_limit(tmp_path: Path, monkeypatch) -> None:
    message = ('雪\nquote=" slash=\\ tab=\t ' * 1000) + "尾"

    class RaisingExtractor:
        def extract_endpoints(self):
            raise RuntimeError(message)

    monkeypatch.setattr(runtime_worker, "_extractor", lambda _request: RaisingExtractor())
    monkeypatch.setattr(runtime_worker, "_container_process_rss_bytes", lambda: None)
    request = json.loads(_request(tmp_path))
    request["output_limit_bytes"] = runtime_worker.MIN_PROTOCOL_OUTPUT_BYTES

    payload, status = runtime_worker.run_request(json.dumps(request))

    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert status == 1
    assert payload["status"] == "error"
    assert payload["message"].startswith('雪\nquote=" slash=\\ tab=\t ')
    assert len(encoded) + 1 <= request["output_limit_bytes"]


def test_too_small_v3_limit_is_rejected_before_work_and_serialization(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    request = json.loads(_request(tmp_path))
    request["output_limit_bytes"] = runtime_worker.MIN_PROTOCOL_OUTPUT_BYTES - 1
    raw_request = json.dumps(request)

    def unexpected_extractor(_request):
        raise AssertionError("application extraction must not start below protocol minimum")

    monkeypatch.setattr(runtime_worker, "_extractor", unexpected_extractor)
    monkeypatch.setattr(sys, "argv", ["runtime_worker", "--request-json", raw_request])

    assert runtime_worker.main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.out.encode("utf-8")) <= request["output_limit_bytes"]


def _host_request(app: Path, *, output_limit: int) -> dict[str, object]:
    return {
        "schema_version": 2,
        "app_path": str(app),
        "app_variable": "app",
        "app_entry": None,
        "bootstrap_entry": None,
        "dependency_max_depth": 10,
        "dependency_max_nodes": 4096,
        "dependency_max_work": 65536,
        "output_limit_bytes": output_limit,
    }


def test_host_worker_unicode_error_file_respects_utf8_limit(tmp_path: Path, monkeypatch) -> None:
    message = ('路\n\\nested=" \u00e9 ' * 1000) + "終"

    class RaisingExtractor:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def _extract_endpoints_in_process(self):
            raise RuntimeError(message)

    monkeypatch.setattr(runtime_worker, "FastAPIExtractor", RaisingExtractor)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            json.dumps(
                _host_request(
                    tmp_path,
                    output_limit=runtime_worker.MIN_PROTOCOL_OUTPUT_BYTES,
                )
            )
        ),
    )
    result_path = tmp_path / "host-result.json"

    assert runtime_worker._run_host_request(result_path) == 1

    encoded = result_path.read_bytes()
    payload = json.loads(encoded)
    assert payload["status"] == "error"
    assert payload["message"].startswith('路\n\\nested=" é ')
    assert len(encoded) <= runtime_worker.MIN_PROTOCOL_OUTPUT_BYTES


def test_too_small_host_limit_is_rejected_before_work_or_file_output(
    tmp_path: Path, monkeypatch
) -> None:
    class UnexpectedExtractor:
        def __init__(self, *_args, **_kwargs) -> None:
            raise AssertionError("application extraction must not start below protocol minimum")

    monkeypatch.setattr(runtime_worker, "FastAPIExtractor", UnexpectedExtractor)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            json.dumps(
                _host_request(
                    tmp_path,
                    output_limit=runtime_worker.MIN_PROTOCOL_OUTPUT_BYTES - 1,
                )
            )
        ),
    )
    result_path = tmp_path / "host-result.json"

    assert runtime_worker._run_host_request(result_path) == 2
    assert not result_path.exists()


def test_worker_analyze_uses_the_selected_runtime_inventory(tmp_path: Path, monkeypatch) -> None:
    _toy_project(tmp_path)
    diff = tmp_path / "change.diff"
    diff.write_text("", encoding="utf-8")
    monkeypatch.setattr(runtime_worker, "_container_process_rss_bytes", lambda: None)

    payload, status = runtime_worker.run_request(_request(tmp_path, phase="analyze", diff=diff))

    assert status == 0, payload
    assert payload["status"] == "ok"
    assert payload["phase"] == "analyze"
    assert payload["total_endpoints"] == 1
    assert payload["candidate_endpoints"] == []
