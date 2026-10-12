"""Public mapper regressions for forwarded partial captures and conditional execution."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import Config, ParserConfig


def _diff(line: int) -> str:
    return (
        "diff --git a/helpers.py b/helpers.py\n"
        "--- a/helpers.py\n+++ b/helpers.py\n"
        f"@@ -{line},1 +{line},1 @@\n"
        "-    return 1\n+    return 2\n"
    )


def _mapper(tmp_path: Path) -> ChangeMapper:
    return ChangeMapper(
        tmp_path,
        config=Config(parser=ParserConfig(follow_imports=False)),
        secure_ast=True,
        use_cache=False,
    )


def _helpers(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\n"
        "def second():\n    return 1\n\n"
        "def run(callback):\n    return callback()\n\n"
        "def invoke(callback):\n    return callback()\n\n"
        "def invoke_override(callback, replacement):\n"
        "    return callback(callback=replacement)\n",
        encoding="utf-8",
    )


def test_partial_forwarding_preserves_capture_and_keyword_override(tmp_path: Path) -> None:
    _helpers(tmp_path)
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run, invoke, invoke_override\n"
        "app = FastAPI()\n"
        "@app.get('/forward')\ndef forward():\n"
        "    bound = partial(run, callback=first)\n    return invoke(bound)\n"
        "@app.get('/override')\ndef override():\n"
        "    bound = partial(run, callback=first)\n"
        "    return invoke_override(bound, second)\n",
        encoding="utf-8",
    )
    mapper = _mapper(tmp_path)
    first_change = mapper.analyze_diff(_diff(2))
    second_change = mapper.analyze_diff(_diff(5))
    assert {item.endpoint.identifier for item in first_change.candidate_endpoints} == {
        "GET /forward"
    }
    assert {item.endpoint.identifier for item in second_change.candidate_endpoints} == {
        "GET /override"
    }


def test_alternative_partials_keep_each_capture_as_low_evidence(tmp_path: Path) -> None:
    _helpers(tmp_path)
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run, invoke\n"
        "app = FastAPI()\n@app.get('/joined')\ndef joined(flag: bool):\n"
        "    if flag:\n        bound = partial(run, callback=first)\n"
        "    else:\n        bound = partial(run, callback=second)\n"
        "    return invoke(bound)\n",
        encoding="utf-8",
    )
    mapper = _mapper(tmp_path)
    for line in (2, 5):
        report = mapper.analyze_diff(_diff(line))
        assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /joined"}
        assert all(item.confidence.value == "low" for item in report.candidate_endpoints)
        endpoint = mapper.registry.get_all()[0]
        dependencies = mapper.mypy_analyzer.get_endpoint_dependencies(endpoint)
        assert dependencies is not None
        assert dependencies.references_lines_low_only(str(tmp_path / "helpers.py"), {line})


def test_nested_partial_capture_abstains_from_later_rebinding(tmp_path: Path) -> None:
    _helpers(tmp_path)
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run, invoke\n"
        "app = FastAPI()\n@app.get('/nested')\ndef nested():\n"
        "    inner = partial(first)\n    outer = partial(run, callback=inner)\n"
        "    inner = partial(second)\n    return invoke(outer)\n",
        encoding="utf-8",
    )
    mapper = _mapper(tmp_path)
    for line in (2, 5):
        report = mapper.analyze_diff(_diff(line))
        assert report.candidate_endpoints == []
        assert report.analysis_completeness == "partial"
        assert any(
            item.cap == "NESTED_PARTIAL_CAPTURE_UNSUPPORTED" for item in report.analysis_limitations
        )


def test_unknown_partial_keyword_expansion_does_not_promote_stale_capture(tmp_path: Path) -> None:
    _helpers(tmp_path)
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run\n"
        "app = FastAPI()\n@app.get('/star')\ndef star():\n"
        "    bound = partial(run, callback=first)\n"
        "    options = {'callback': second}\n    return bound(**options)\n",
        encoding="utf-8",
    )
    mapper = _mapper(tmp_path)
    report = mapper.analyze_diff(_diff(2))
    assert report.candidate_endpoints == []
    assert report.analysis_completeness == "partial"
    assert any(item.cap == "UNRESOLVED_PARTIAL_ARGUMENTS" for item in report.analysis_limitations)


def test_exception_type_lambda_is_possible_without_established_body_span(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def target():\n    return 1\n\ndef risky():\n    raise ValueError\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import target, risky\n"
        "app = FastAPI()\n@app.get('/exception-type')\ndef exception_type():\n"
        "    callback = lambda: (target(), ValueError)[1]\n"
        "    try:\n        risky()\n    except callback():\n        pass\n    return 0\n",
        encoding="utf-8",
    )
    mapper = _mapper(tmp_path)
    report = mapper.analyze_diff(_diff(2))
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
        "GET /exception-type"
    }
    endpoint = mapper.registry.get_all()[0]
    dependencies = mapper.mypy_analyzer.get_endpoint_dependencies(endpoint)
    assert dependencies is not None
    spans = dependencies.get_source_evidence_spans(str(tmp_path / "main.py"))
    assert any(
        span.start_line == 6 and span.execution_state == "possible_execution" for span in spans
    )
    assert not any(
        span.start_line == 6 and span.execution_state == "established_execution" for span in spans
    )
