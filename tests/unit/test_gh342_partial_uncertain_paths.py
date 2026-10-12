"""Public mapper controls for uncertain partial paths and keyword-only forwarding."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import Config, ParserConfig


def _mapper(tmp_path: Path, handlers: str) -> ChangeMapper:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\n"
        "def second():\n    return 1\n\n"
        "def run(callback):\n    return callback()\n\n"
        "def invoke(callback):\n    return callback()\n\n"
        "def invoke_keyword(*, callback):\n    return callback()\n\n"
        "def risky():\n    raise ValueError\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run, invoke, invoke_keyword, risky\n"
        "app = FastAPI()\n" + handlers,
        encoding="utf-8",
    )
    return ChangeMapper(
        tmp_path,
        config=Config(parser=ParserConfig(follow_imports=False)),
        secure_ast=True,
        use_cache=False,
    )


def _diff(line: int) -> str:
    return (
        "diff --git a/helpers.py b/helpers.py\n"
        "--- a/helpers.py\n+++ b/helpers.py\n"
        f"@@ -{line},1 +{line},1 @@\n"
        "-    return 1\n+    return 2\n"
    )


def test_missing_partial_branch_reports_unknown_and_keeps_known_target_low(tmp_path: Path) -> None:
    mapper = _mapper(
        tmp_path,
        "@app.get('/unknown')\ndef unknown(flag: bool, replacement):\n"
        "    if flag:\n        bound = partial(run, callback=first)\n"
        "    else:\n        bound = replacement\n"
        "    return invoke(bound)\n",
    )
    report = mapper.analyze_diff(_diff(2))
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /unknown"}
    assert all(item.confidence.value == "low" for item in report.candidate_endpoints)
    assert report.analysis_completeness == "partial"
    assert any(item.cap == "UNKNOWN_PARTIAL_BINDING" for item in report.analysis_limitations)
    endpoint = mapper.registry.get_all()[0]
    dependencies = mapper.mypy_analyzer.get_endpoint_dependencies(endpoint)
    assert dependencies is not None
    assert dependencies.references_lines_low_only(str(tmp_path / "helpers.py"), {2})


def test_try_completed_partial_captures_remain_independent_low_targets(tmp_path: Path) -> None:
    mapper = _mapper(
        tmp_path,
        "@app.get('/try-join')\ndef try_join():\n"
        "    try:\n        risky()\n        bound = partial(run, callback=first)\n"
        "    except ValueError:\n        bound = partial(run, callback=second)\n"
        "    return invoke(bound)\n",
    )
    for line in (2, 5):
        report = mapper.analyze_diff(_diff(line))
        assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
            "GET /try-join"
        }
        assert all(item.confidence.value == "low" for item in report.candidate_endpoints)
        endpoint = mapper.registry.get_all()[0]
        dependencies = mapper.mypy_analyzer.get_endpoint_dependencies(endpoint)
        assert dependencies is not None
        assert dependencies.references_lines_low_only(str(tmp_path / "helpers.py"), {line})


def test_terminal_partial_branch_does_not_enter_continuing_join(tmp_path: Path) -> None:
    mapper = _mapper(
        tmp_path,
        "@app.get('/terminal')\ndef terminal(flag: bool):\n"
        "    if flag:\n        bound = partial(run, callback=first)\n        return 0\n"
        "    else:\n        bound = partial(run, callback=second)\n"
        "    return invoke(bound)\n",
    )
    assert mapper.analyze_diff(_diff(2)).candidate_endpoints == []
    report = mapper.analyze_diff(_diff(5))
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /terminal"}


def test_keyword_only_forwarding_preserves_partial_capture(tmp_path: Path) -> None:
    mapper = _mapper(
        tmp_path,
        "@app.get('/keyword')\ndef keyword():\n"
        "    bound = partial(run, callback=first)\n"
        "    return invoke_keyword(callback=bound)\n",
    )
    report = mapper.analyze_diff(_diff(2))
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /keyword"}
    assert mapper.analyze_diff(_diff(5)).candidate_endpoints == []


def test_variadic_forwarding_reports_lost_partial_capture(tmp_path: Path) -> None:
    mapper = _mapper(
        tmp_path,
        "def forward(*args):\n    return invoke(*args)\n"
        "@app.get('/variadic')\ndef variadic():\n"
        "    bound = partial(run, callback=first)\n"
        "    return forward(bound)\n",
    )
    report = mapper.analyze_diff(_diff(2))
    assert report.candidate_endpoints == []
    assert report.analysis_completeness == "partial"
    assert any(
        item.cap == "UNRESOLVED_PARTIAL_ARGUMENTS"
        and item.file_path == str(tmp_path / "main.py")
        and item.call_line == 10
        for item in report.analysis_limitations
    )


def test_inline_partial_into_variadic_signature_reports_capture_limit(tmp_path: Path) -> None:
    mapper = _mapper(
        tmp_path,
        "def forward(*args):\n    return invoke(*args)\n"
        "@app.get('/inline-variadic')\ndef inline_variadic():\n"
        "    return forward(partial(first))\n",
    )
    report = mapper.analyze_diff(_diff(2))
    assert report.candidate_endpoints == []
    assert report.analysis_completeness == "partial"
    assert any(
        item.cap == "INLINE_PARTIAL_ARGUMENT_UNSUPPORTED"
        and item.file_path == str(tmp_path / "main.py")
        and item.call_line == 9
        for item in report.analysis_limitations
    )


def test_partial_constructor_in_starred_list_has_caller_limitation(tmp_path: Path) -> None:
    mapper = _mapper(
        tmp_path,
        "def forward(*args):\n    return invoke(*args)\n"
        "@app.get('/star-list')\ndef star_list():\n"
        "    return forward(*[partial(first)])\n",
    )
    report = mapper.analyze_diff(_diff(2))
    assert report.candidate_endpoints == []
    assert report.analysis_completeness == "partial"
    assert any(
        item.cap == "INLINE_PARTIAL_ARGUMENT_UNSUPPORTED"
        and item.file_path == str(tmp_path / "main.py")
        and item.call_line == 9
        for item in report.analysis_limitations
    )


def test_partial_constructor_in_expanded_dict_has_caller_limitation(tmp_path: Path) -> None:
    mapper = _mapper(
        tmp_path,
        "def forward(**kwargs):\n    return invoke(**kwargs)\n"
        "@app.get('/star-dict')\ndef star_dict():\n"
        "    return forward(**{'callback': partial(first)})\n",
    )
    report = mapper.analyze_diff(_diff(2))
    assert report.candidate_endpoints == []
    assert report.analysis_completeness == "partial"
    assert any(
        item.cap == "INLINE_PARTIAL_ARGUMENT_UNSUPPORTED"
        and item.file_path == str(tmp_path / "main.py")
        and item.call_line == 9
        for item in report.analysis_limitations
    )
