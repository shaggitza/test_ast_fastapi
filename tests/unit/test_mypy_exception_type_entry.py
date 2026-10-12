"Public call-site controls for exception-type evaluation state."

from pathlib import Path

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus, ResolvedCallSite
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(path: Path, *, line: int, name: str = "handler") -> Endpoint:
    return Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name=name,
            module=path.stem,
            file_path=path,
            line_number=line,
        ),
    )


def _site_by_spelling(sites: list[ResolvedCallSite], spelling: str) -> list[ResolvedCallSite]:
    return [site for site in sites if site.source_spelling == spelling]


def test_except_type_uses_exception_entry_alias_not_normal_body_alias(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first_type() -> type[Exception]:\n    return ValueError\n\n"
        "def second_type() -> type[Exception]:\n    return RuntimeError\n\n"
        "def risky() -> None:\n    pass\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from helpers import first_type, second_type, risky\n\n"
        "def handler() -> None:\n"
        "    callback = first_type\n"
        "    try:\n"
        "        risky()\n"
        "        callback = second_type\n"
        "    except callback():\n"
        "        pass\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=3))

    type_calls = [
        site
        for site in _site_by_spelling(deps.get_resolved_call_sites(str(main)), "callback")
        if site.line == 8
    ]
    assert len(type_calls) == 1
    assert type_calls[0].status == CallResolutionStatus.EXACT
    assert type_calls[0].canonical_symbol is not None
    assert type_calls[0].canonical_symbol.endswith("helpers.first_type")
    first_refs = [ref for ref in deps.referenced_symbols if ref.symbol_name.endswith("first_type")]
    assert first_refs and all(ref.low_confidence for ref in first_refs)
    assert not any(
        ref.symbol_name.endswith("second_type") and not ref.low_confidence
        for ref in deps.referenced_symbols
    )


def test_later_except_type_does_not_inherit_prior_handler_body_rebind(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first_type() -> type[Exception]:\n    return ValueError\n\n"
        "def second_type() -> type[Exception]:\n    return RuntimeError\n\n"
        "def risky() -> None:\n    pass\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from helpers import first_type, second_type, risky\n\n"
        "def handler() -> None:\n"
        "    callback = first_type\n"
        "    try:\n"
        "        risky()\n"
        "    except ValueError:\n"
        "        callback = second_type\n"
        "    except callback():\n"
        "        pass\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=3))

    type_calls = [
        site
        for site in _site_by_spelling(deps.get_resolved_call_sites(str(main)), "callback")
        if site.line == 9
    ]
    assert len(type_calls) == 1
    assert type_calls[0].status == CallResolutionStatus.EXACT
    assert type_calls[0].canonical_symbol is not None
    assert type_calls[0].canonical_symbol.endswith("helpers.first_type")
    first_refs = [ref for ref in deps.referenced_symbols if ref.symbol_name.endswith("first_type")]
    assert first_refs and all(ref.low_confidence for ref in first_refs)
    assert not any(
        ref.symbol_name.endswith("second_type") and not ref.low_confidence
        for ref in deps.referenced_symbols
    )
