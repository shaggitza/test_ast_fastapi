"""Constructed method calls need proven allocation and ordinary instance lookup."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import EndpointDependencies, MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus, ResolvedCallSite
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _analyze_member(
    tmp_path: Path,
    model_source: str,
    expression: str,
    *,
    parameters: str = "",
    imports: str = "from models import Concrete",
    setup: str = "",
) -> tuple[EndpointDependencies, ResolvedCallSite]:
    (tmp_path / "models.py").write_text(model_source, encoding="utf-8")
    main = tmp_path / "main.py"
    prefix = f"from typing import Any\n{imports}\n"
    if setup:
        prefix += setup.rstrip() + "\n"
    prefix += "\n"
    handler_line = prefix.count("\n") + 1
    main.write_text(
        prefix + f"def handler({parameters}):\n    return {expression}\n",
        encoding="utf-8",
    )
    endpoint = Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler", module="main", file_path=main, line_number=handler_line
        ),
    )
    deps = MypyAnalyzer(tmp_path, module_root=tmp_path).analyze_endpoint(endpoint)
    sites = [
        site
        for site in deps.resolved_call_sites
        if Path(site.file_path).resolve() == main.resolve()
        and site.line == handler_line + 1
        and site.source_spelling.endswith(".run")
    ]
    assert len(sites) == 1
    return deps, sites[0]


def _assert_receiver_abstention(
    deps: EndpointDependencies, site: ResolvedCallSite, reason: str
) -> None:
    assert site.status == CallResolutionStatus.AMBIGUOUS
    assert site.canonical_symbol is None
    assert site.invocation is None
    assert site.reason_code == reason
    assert any(
        item.call_line == site.line
        and Path(item.file_path).resolve() == Path(site.file_path).resolve()
        and item.call_column == site.column
        and item.cap == reason.upper()
        for item in deps.analysis_limitations
    )


@pytest.mark.parametrize(
    ("model_source", "expected_symbol"),
    (
        (
            "class Concrete:\n    label = 'stable'\n    def run(self) -> int: return 1\n",
            "models.Concrete.run",
        ),
        (
            "class Base:\n    def run(self) -> int: return 1\nclass Concrete(Base):\n    pass\n",
            "models.Base.run",
        ),
    ),
    ids=("default-allocation", "inherited-method-owner"),
)
def test_default_constructor_preserves_exact_method_owner(
    tmp_path: Path, model_source: str, expected_symbol: str
) -> None:
    _deps, site = _analyze_member(tmp_path, model_source, "Concrete().run()")
    assert site.status == CallResolutionStatus.EXACT
    assert site.canonical_symbol == expected_symbol


@pytest.mark.parametrize(
    "model_source",
    (
        "from typing import Any\n"
        "class Proxy:\n    def run(self) -> int: return 2\n"
        "class Concrete:\n"
        "    def __new__(cls) -> Any: return Proxy()\n"
        "    def run(self) -> int: return 1\n",
        "from typing import Any, final\n"
        "class Proxy:\n    def run(self) -> int: return 2\n"
        "@final\n"
        "class Concrete:\n"
        "    def __new__(cls) -> Any: return Proxy()\n"
        "    @final\n"
        "    def run(self) -> int: return 1\n",
        "from typing import Any, final\n"
        "class Proxy:\n    def run(self) -> int: return 2\n"
        "class Meta(type):\n"
        "    def __call__(cls) -> Any: return Proxy()\n"
        "@final\n"
        "class Concrete(metaclass=Meta):\n"
        "    def run(self) -> int: return 1\n",
        "from typing import Any\n"
        "class Proxy:\n    def run(self) -> int: return 2\n"
        "class AllocatorBase:\n"
        "    def __new__(cls) -> Any: return Proxy()\n"
        "class Concrete(AllocatorBase):\n"
        "    def run(self) -> int: return 1\n",
        "from typing import Any, Callable\n"
        "class Proxy:\n    def run(self) -> int: return 2\n"
        "class Concrete:\n"
        "    @property\n"
        "    def run(self) -> Callable[[], int]: return Proxy().run\n",
        "from typing import Any\n"
        "def replacement(self: Any) -> int: return 2\n"
        "class Installer:\n"
        "    def __set_name__(self, owner: Any, name: str) -> None:\n"
        "        owner.run = replacement\n"
        "class Concrete:\n"
        "    install = Installer()\n"
        "    def run(self) -> int: return 1\n",
    ),
    ids=(
        "custom-new",
        "final-custom-new",
        "final-custom-metaclass",
        "inherited-custom-new",
        "property-returned-callable",
        "class-descriptor-installation",
    ),
)
def test_unproven_allocation_cannot_promote_a_method_declaration(
    tmp_path: Path, model_source: str
) -> None:
    deps, site = _analyze_member(tmp_path, model_source, "Concrete().run()")
    _assert_receiver_abstention(deps, site, "unproven_receiver_construction")


@pytest.mark.parametrize(
    "model_source",
    (
        "from typing import Any\n"
        "class Proxy:\n    def run(self) -> int: return 2\n"
        "class Concrete:\n"
        "    def __getattribute__(self, name: str) -> Any:\n"
        "        if name == 'run': return Proxy().run\n"
        "        return object.__getattribute__(self, name)\n"
        "    def run(self) -> int: return 1\n",
        "from typing import Any\n"
        "class Proxy:\n    def run(self) -> int: return 2\n"
        "class Concrete:\n"
        "    def __getattribute__(self, name: str) -> Any:\n"
        "        raise AttributeError(name)\n"
        "    def __getattr__(self, name: str) -> Any:\n"
        "        if name == 'run': return Proxy().run\n"
        "        raise AttributeError(name)\n"
        "    def run(self) -> int: return 1\n",
    ),
    ids=("getattribute", "getattr-fallback"),
)
def test_custom_instance_lookup_cannot_promote_the_nominal_method(
    tmp_path: Path, model_source: str
) -> None:
    deps, site = _analyze_member(tmp_path, model_source, "Concrete().run()")
    _assert_receiver_abstention(deps, site, "unproven_receiver_lookup")


@pytest.mark.parametrize(
    ("expression", "parameters"),
    (
        ("Concrete(1).run()", ""),
        ("Concrete(value=1).run()", ""),
        ("Concrete(*args).run()", "args: Any"),
        ("Concrete(**kwargs).run()", "kwargs: Any"),
    ),
    ids=("positional", "keyword", "starargs", "starstarargs"),
)
def test_supplied_constructor_actuals_do_not_prove_an_exact_receiver(
    tmp_path: Path, expression: str, parameters: str
) -> None:
    # Valid custom initialization; isolated argument-shape controls also cover
    # the shared helper without relying on diagnostics for invalid object calls.
    model = (
        "from typing import Any\n"
        "class Concrete:\n"
        "    def __init__(self, *args: Any, **kwargs: Any) -> None: pass\n"
        "    def run(self) -> int: return 1\n"
    )
    deps, site = _analyze_member(tmp_path, model, expression, parameters=parameters)
    _assert_receiver_abstention(deps, site, "unproven_receiver_construction")


@pytest.mark.parametrize(
    "mutation",
    (
        "Concrete.run = replacement",
        "setattr(Concrete, 'run', replacement)",
        "delattr(Concrete, 'run')",
        "Alias = Concrete\nAlias.run = replacement",
        "Alias = Concrete\nsetattr(Alias, 'run', replacement)",
        "def install(target: type[Concrete]) -> None:\n"
        "    setattr(target, 'run', replacement)\n"
        "install(Concrete)",
        "type.__setattr__(Concrete, 'run', replacement)",
        "type.__delattr__(Concrete, 'run')",
        "def install(values: list[object]) -> None:\n"
        "    setattr(values[0], 'run', replacement)\n"
        "install([Concrete])",
        "def install(values: dict[str, object]) -> None:\n"
        "    setattr(values['target'], 'run', replacement)\n"
        "install({'target': Concrete})",
        "values: list[object] = [Concrete]\n"
        "def install(items: list[object]) -> None:\n"
        "    setattr(items[0], 'run', replacement)\n"
        "install(values)",
        "def install(factory: Any) -> None:\n"
        "    setattr(factory(), 'run', replacement)\n"
        "install(lambda: Concrete)",
        "def install(factory: Any) -> None:\n"
        "    setattr(factory()[0], 'run', replacement)\n"
        "install(lambda: [Concrete])",
    ),
    ids=(
        "direct-assignment",
        "setattr",
        "delattr",
        "class-alias-assignment",
        "class-alias-setattr",
        "helper-parameter",
        "type-setattr",
        "type-delattr",
        "literal-list-escape",
        "literal-dict-escape",
        "aliased-list-escape",
        "lambda-class-escape",
        "lambda-list-escape",
    ),
)
def test_source_visible_class_mutation_invalidates_exact_lookup(
    tmp_path: Path, mutation: str
) -> None:
    model = (
        "from typing import Any\n"
        "class Concrete:\n    def run(self) -> int: return 1\n"
        "def replacement(self: Any) -> int: return 2\n"
        f"{mutation}\n"
    )
    deps, site = _analyze_member(tmp_path, model, "Concrete().run()")
    _assert_receiver_abstention(deps, site, "unproven_receiver_lookup")


_BINDING_MODEL = (
    "from typing import Any\n"
    "class Concrete:\n    def run(self) -> int: return 1\n"
    "class Proxy:\n    def run(self) -> int: return 2\n"
)


@pytest.mark.parametrize(
    "mutation",
    (
        "Concrete = Proxy",
        "Concrete: Any = Proxy",
        "Concrete, other = Proxy, 1",
        "del Concrete",
        "def install() -> None:\n    global Concrete\n    Concrete = Proxy\ninstall()",
        "for Concrete in [Proxy]:\n    pass",
        "try:\n    raise RuntimeError()\nexcept RuntimeError as Concrete:\n    pass",
        "def Concrete() -> Proxy:\n    return Proxy()",
    ),
    ids=(
        "class-name-assignment",
        "annotated-class-name-assignment",
        "destructured-class-name",
        "class-name-delete",
        "global-class-name",
        "loop-class-name",
        "exception-class-name",
        "function-replaces-class",
    ),
)
def test_visible_class_binding_changes_cannot_promote_the_original_type(
    tmp_path: Path, mutation: str
) -> None:
    deps, site = _analyze_member(tmp_path, _BINDING_MODEL + mutation + "\n", "Concrete().run()")
    # Error-tolerant graphs may keep the original TypeInfo or replace it with
    # an unresolved binding. Neither representation proves the physical call.
    assert site.status != CallResolutionStatus.EXACT
    assert site.canonical_symbol is None
    assert site.invocation is None
    assert not any(ref.symbol_name == "models.Concrete.run" for ref in deps.referenced_symbols)


@pytest.mark.parametrize(
    "setup",
    (
        "C = Proxy",
        "C: Any = Proxy",
        "del C",
        "def install() -> None:\n    global C\n    C = Proxy\ninstall()",
    ),
    ids=(
        "import-alias-assignment",
        "import-alias-annotation",
        "import-alias-delete",
        "global-alias",
    ),
)
def test_rebound_import_alias_does_not_preserve_the_original_class(
    tmp_path: Path, setup: str
) -> None:
    deps, site = _analyze_member(
        tmp_path,
        _BINDING_MODEL,
        "C().run()",
        imports="from models import Concrete as C, Proxy",
        setup=setup,
    )
    assert site.status != CallResolutionStatus.EXACT
    assert site.canonical_symbol is None
    assert site.invocation is None
    assert not any(ref.symbol_name == "models.Concrete.run" for ref in deps.referenced_symbols)


@pytest.mark.parametrize(
    "unrelated_source",
    (
        "def local_shadow() -> int:\n    Concrete = Proxy\n    return Concrete().run()",
        "def parameter_shadow(Concrete: Proxy) -> int:\n    return Concrete.run()",
        "other = Proxy",
    ),
    ids=("function-local-shadow", "parameter-local-shadow", "unrelated-module-name"),
)
def test_unrelated_local_names_preserve_the_module_constructor(
    tmp_path: Path, unrelated_source: str
) -> None:
    _deps, site = _analyze_member(
        tmp_path, _BINDING_MODEL + unrelated_source + "\n", "Concrete().run()"
    )
    assert site.status == CallResolutionStatus.EXACT
    assert site.canonical_symbol == "models.Concrete.run"


def test_unchanged_import_alias_preserves_the_exact_constructor(tmp_path: Path) -> None:
    _deps, site = _analyze_member(
        tmp_path, _BINDING_MODEL, "C().run()", imports="from models import Concrete as C"
    )
    assert site.status == CallResolutionStatus.EXACT
    assert site.canonical_symbol == "models.Concrete.run"


@pytest.mark.parametrize(
    "capture",
    ("Concrete", "_ as Concrete", "[*Concrete]"),
    ids=("capture-pattern", "as-pattern", "star-pattern"),
)
def test_module_pattern_capture_invalidates_the_constructor_binding(
    tmp_path: Path, capture: str
) -> None:
    model = _BINDING_MODEL + f"match [Proxy]:\n    case {capture}:\n        pass\n"
    deps, site = _analyze_member(tmp_path, model, "Concrete().run()")
    assert site.status != CallResolutionStatus.EXACT
    assert site.canonical_symbol is None
    assert site.invocation is None
    assert not any(ref.symbol_name == "models.Concrete.run" for ref in deps.referenced_symbols)


def test_local_pattern_capture_does_not_change_the_module_binding(tmp_path: Path) -> None:
    model = (
        _BINDING_MODEL + "def local_capture(value: object) -> None:\n"
        "    match value:\n        case Concrete:\n            pass\n"
    )
    _deps, site = _analyze_member(tmp_path, model, "Concrete().run()")
    assert site.status == CallResolutionStatus.EXACT
    assert site.canonical_symbol == "models.Concrete.run"


def test_wildcard_import_cannot_preserve_an_earlier_constructor_binding(tmp_path: Path) -> None:
    (tmp_path / "replacement.py").write_text(
        "class Concrete:\n    def run(self) -> int: return 2\n", encoding="utf-8"
    )
    deps, site = _analyze_member(
        tmp_path, _BINDING_MODEL + "from replacement import *\n", "Concrete().run()"
    )
    assert site.status != CallResolutionStatus.EXACT
    assert site.canonical_symbol is None
    assert site.invocation is None
    assert not any(ref.symbol_name == "models.Concrete.run" for ref in deps.referenced_symbols)
