from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.client_observations import established_surfaces
from fastapi_endpoint_detector.analyzer.project_observations import (
    SourceObservationIssue,
    scan_project_observations,
)
from fastapi_endpoint_detector.parser.secure_ast_extractor import SecureASTExtractor


def test_project_adapter_preserves_occurrences_queries_and_explicit_origin_join(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "client.ts").write_text(
        "fetch('https://api.example.test/items?q=1');\n"
        "fetch('https://api.example.test/items?q=1');\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "Component.svelte").write_text(
        "<div>fetch('https://api.example.test/markup')</div>\n"
        "<script>fetch('https://api.example.test/from-script');</script>\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        "API_BASE_URL=https://api.example.test\nOTHER_SECRET=hidden\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text(
        'EXPOSE 8000\nCMD ["uvicorn", "app:app"]\n',
        encoding="utf-8",
    )
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker" / "build_and_push_base.Dockerfile").write_text(
        'ENTRYPOINT ["python", "-m", "app"]\n', encoding="utf-8"
    )
    (tmp_path / "launch.py").write_text(
        "import subprocess as sp\nsp.run(['echo', 'ok'])\n", encoding="utf-8"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.ts").write_text(
        "fetch('https://api.example.test/ignored')", encoding="utf-8"
    )
    server_path = tmp_path / "server.py"
    server_path.write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items(): pass\n",
        encoding="utf-8",
    )

    endpoint = SecureASTExtractor(server_path).extract_endpoints()[0]
    surface_id = established_surfaces([endpoint])[0].surface_id
    snapshot = scan_project_observations(
        tmp_path,
        endpoints=(endpoint,),
        trusted_server_origins={surface_id: "https://api.example.test"},
    )

    assert snapshot.complete
    assert [item.route_path for item in snapshot.client_observations] == [
        "/from-script",
        "/items",
        "/items",
    ]
    assert [item.query for item in snapshot.client_observations] == [None, "q=1", "q=1"]
    assert len({(item.start_offset, item.end_offset) for item in snapshot.client_observations}) == 3
    assert [item.surface_id for item in snapshot.surface_matches] == [
        surface_id,
        surface_id,
    ]
    source_report = snapshot.to_dict()
    assert source_report["trusted_server_origins"] == {surface_id: "https://api.example.test"}
    assert source_report["budgets"] == {"max_files": 10_000, "max_file_bytes": 2_000_000}
    assert any(
        item.kind == "environment" and item.key == "OTHER_SECRET" and item.value is None
        for item in snapshot.deployment_observations
    )
    assert any(
        item.kind == "exposed_port" and item.value == "8000"
        for item in snapshot.deployment_observations
    )
    assert any(item.kind == "container_argv" for item in snapshot.deployment_observations)
    assert any(
        item.source_path.as_posix() == "docker/build_and_push_base.Dockerfile"
        and item.kind == "container_argv"
        for item in snapshot.deployment_observations
    )
    assert any(
        item.kind == "subprocess_argv" and item.certainty == "exact"
        for item in snapshot.deployment_observations
    )


def test_project_adapter_never_infers_origin_or_trust(tmp_path: Path) -> None:
    (tmp_path / "client.ts").write_text(
        "fetch('https://api.example.test/items'); fetch(`${origin}/dynamic`);",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text("API_BASE_URL=${API_ORIGIN}\n", encoding="utf-8")
    snapshot = scan_project_observations(tmp_path)

    assert not snapshot.surface_matches
    assert [item.reason for item in snapshot.client_uncertainties] == ["dynamic_or_nonliteral_url"]
    assert snapshot.deployment_observations[0].certainty == "uncertain"
    assert snapshot.to_dict()["scope"] == "bounded_source_observations_only"
    with pytest.raises(ValueError, match="not established"):
        scan_project_observations(
            tmp_path,
            trusted_server_origins={"invented:route": "https://api.example.test"},
        )


def test_project_adapter_reports_budget_skips_as_incomplete(tmp_path: Path) -> None:
    (tmp_path / "a.ts").write_text("fetch('/a')", encoding="utf-8")
    (tmp_path / "b.ts").write_text("fetch('/b')", encoding="utf-8")

    snapshot = scan_project_observations(tmp_path, max_files=1)

    assert snapshot.scanned_files == 1
    assert not snapshot.complete
    assert len(snapshot.issues) == 1
    assert snapshot.issues[0].reason == "maximum source-file count reached"


def test_project_adapter_reports_oversized_file_and_continues(tmp_path: Path) -> None:
    (tmp_path / "large.ts").write_text("fetch('/oversized-path')", encoding="utf-8")
    (tmp_path / "small.ts").write_text("fetch('/x')", encoding="utf-8")

    snapshot = scan_project_observations(tmp_path, max_file_bytes=15)

    assert not snapshot.complete
    assert [item.route_path for item in snapshot.client_observations] == ["/x"]
    assert snapshot.issues[0].reason == "maximum source-file size exceeded"


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "https://user:pass@example.test",
        "https://example.test/path",
        "https://example.test:bad",
        "https://example.test:",
        "ftp://example.test",
    ],
)
def test_project_adapter_rejects_malformed_or_non_origin_trust_values(
    tmp_path: Path, origin: str
) -> None:
    (tmp_path / "client.ts").write_text("fetch('/items')", encoding="utf-8")
    server_path = tmp_path / "server.py"
    server_path.write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items(): pass\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(server_path).extract_endpoints()[0]
    surface_id = established_surfaces([endpoint])[0].surface_id
    with pytest.raises(ValueError, match="trusted server origin"):
        scan_project_observations(
            tmp_path,
            endpoints=(endpoint,),
            trusted_server_origins={surface_id: origin},
        )


@pytest.mark.parametrize(
    "pattern",
    ["", "../src/*.ts", "/tmp/*.ts", "src/[abc.ts", "src/foo\\bar.ts"],
)
def test_project_adapter_rejects_malformed_source_patterns(tmp_path: Path, pattern: str) -> None:
    with pytest.raises(ValueError, match="source selection pattern"):
        scan_project_observations(tmp_path, client_include_patterns=(pattern,))


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_project_adapter_rejects_invalid_scan_budgets(tmp_path: Path, limit: int) -> None:
    with pytest.raises(ValueError, match="limits must be positive"):
        scan_project_observations(tmp_path, max_files=limit)


def test_project_adapter_marks_selected_symlinks_as_incomplete(tmp_path: Path) -> None:
    skipped = tmp_path / "node_modules"
    skipped.mkdir()
    source = skipped / "outside.ts"
    source.write_text("fetch('/outside')", encoding="utf-8")
    (tmp_path / "client.ts").symlink_to(source)

    snapshot = scan_project_observations(tmp_path)

    assert not snapshot.complete
    assert snapshot.client_observations == ()
    assert snapshot.issues == (
        SourceObservationIssue("client.ts", "symlink source was not followed"),
    )
