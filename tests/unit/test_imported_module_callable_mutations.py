"""Imported module helper ownership must fail closed after source rebinding."""

from pathlib import Path
from typing import Any

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _write_httpx_source(module_root: Path) -> None:
    package = module_root / "httpx"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("from ._api import get\n", encoding="utf-8")
    (package / "_api.py").write_text(
        "def get(url: str) -> object:\n    return object()\n", encoding="utf-8"
    )


def _call_sites(app: Path, source: str) -> list[Any]:
    module_root = app.parent / "packages"
    module_root.mkdir()
    _write_httpx_source(module_root)
    fixture = app / "fixture.py"
    fixture.write_text(source, encoding="utf-8")
    handler_line = next(
        line_number
        for line_number, line in enumerate(source.splitlines(), 1)
        if line.startswith("def handler")
    )
    endpoint = Endpoint(
        path="/probe",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler", module="fixture", file_path=fixture, line_number=handler_line
        ),
    )
    dependencies = MypyAnalyzer(
        app, module_root=module_root, max_depth=2, no_site_packages=True, target_platform="linux"
    ).analyze_endpoint(endpoint)
    return dependencies.get_resolved_call_sites()


def test_unmutated_module_and_import_aliases_resolve_exactly(tmp_path: Path) -> None:
    """Direct and imported aliases retain canonical identity without source writes."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "api = client\n"
        "from httpx import get as fetch\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n"
        "    api.get(url)\n"
        "    fetch(url)\n",
    )

    assert [site.status for site in sites] == [
        CallResolutionStatus.EXACT,
        CallResolutionStatus.EXACT,
        CallResolutionStatus.EXACT,
    ]
    assert {site.canonical_symbol for site in sites} == {"httpx._api.get"}


def test_module_and_imported_helper_rebindings_abstain(tmp_path: Path) -> None:
    """Member writes, imported-name writes, and setattr poison exact helper ownership."""
    app = tmp_path / "app"
    app.mkdir()
    source = (
        "import httpx as client\n"
        "from httpx import get as fetch\n"
        "from typing import Any\n"
        "class Foreign:\n"
        "    def get(self, url: str) -> object: ...\n"
        "def handler(url: str, foreign: Foreign, anything: Any, flag: bool, name: str) -> None:\n"
        "    replacement: Any = foreign.get\n"
        "    client.get(url)\n"
        "    client.get = replacement\n"
        "    client.get(url)\n"
        "    fetch = replacement\n"
        "    fetch(url)\n"
        "    if flag:\n"
        "        setattr(client, name, replacement)\n"
        "    client.get(url)\n"
        "    foreign.get(url)\n"
        "    anything.get(url)\n"
    )
    sites = _call_sites(app, source)
    helper_sites = [site for site in sites if site.source_spelling in {"client.get", "fetch"}]
    assert len(helper_sites) == 4
    assert all(site.status != CallResolutionStatus.EXACT for site in helper_sites), [
        (site.source_spelling, site.status, site.reason_code, site.canonical_symbol)
        for site in helper_sites
    ]
    assert all(site.canonical_symbol is None for site in helper_sites)
    assert all(
        site.reason_code == "mutated_imported_callable"
        for site in helper_sites
        if site.source_spelling == "client.get"
    )
    assert next(site for site in sites if site.source_spelling == "foreign.get").status == (
        CallResolutionStatus.AMBIGUOUS
    )
    assert next(site for site in sites if site.source_spelling == "anything.get").status == (
        CallResolutionStatus.UNRESOLVED
    )


def test_shadowed_parameter_write_does_not_mutate_imported_module(tmp_path: Path) -> None:
    """A same-named parameter has its own binding and cannot poison another function."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "def unrelated(client: object, replacement: object) -> None:\n"
        "    client.get = replacement\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.EXACT
    assert handler_call.canonical_symbol == "httpx._api.get"


def test_shadowed_class_binding_write_does_not_mutate_imported_module(tmp_path: Path) -> None:
    """A class namespace binding is independent of the module import alias."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "class Unrelated:\n"
        "    client = object()\n"
        "    client.get = object()\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.EXACT
    assert handler_call.canonical_symbol == "httpx._api.get"


def test_shadowed_comprehension_binding_does_not_mutate_imported_module(tmp_path: Path) -> None:
    """A comprehension target is local to the comprehension body."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "[setattr(client, 'get', object()) for client in (object(),)]\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.EXACT
    assert handler_call.canonical_symbol == "httpx._api.get"


def test_class_method_global_write_mutates_imported_module(tmp_path: Path) -> None:
    """Class namespaces do not shadow a method's explicit global binding."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "class Holder:\n"
        "    client: object\n"
        "    def mutate(self, replacement: object) -> None:\n"
        "        global client\n"
        "        client.get = replacement\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.AMBIGUOUS
    assert handler_call.canonical_symbol is None


def test_nested_global_writes_override_outer_parameter_and_local(tmp_path: Path) -> None:
    """A nested global declaration overrides enclosing same-named locals."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "def outer(client: object, replacement: object) -> None:\n"
        "    def mutate_parameter_scope() -> None:\n"
        "        global client\n"
        "        client.get = replacement\n"
        "def other() -> None:\n"
        "    client = object()\n"
        "    def mutate_local_scope() -> None:\n"
        "        global client\n"
        "        client.get = object()\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.AMBIGUOUS
    assert handler_call.canonical_symbol is None


def test_nested_global_declaration_without_write_preserves_exact_call(tmp_path: Path) -> None:
    """A global declaration alone does not count as a module mutation."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "def unrelated(client: object) -> None:\n"
        "    def nested() -> None:\n"
        "        global client\n"
        "        return\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.EXACT
    assert handler_call.canonical_symbol == "httpx._api.get"


def test_method_local_binding_does_not_mask_class_body_module_write(tmp_path: Path) -> None:
    """Method locals do not become class namespace bindings for sibling statements."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "class Holder:\n"
        "    def unrelated(self) -> None:\n"
        "        client = object()\n"
        "        client.get = object()\n"
        "    client.get = object()\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.AMBIGUOUS
    assert handler_call.canonical_symbol is None


def test_nested_closure_parameter_write_remains_scoped(tmp_path: Path) -> None:
    """A nested closure over a parameter does not mutate the module import."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "def unrelated(client: object) -> None:\n"
        "    def nested() -> None:\n"
        "        client.get = object()\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.EXACT
    assert handler_call.canonical_symbol == "httpx._api.get"


def test_nonlocal_scope_abstains_conservatively(tmp_path: Path) -> None:
    """Unsupported nonlocal alias relationships cannot preserve exact ownership."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "def outer() -> None:\n"
        "    client = object()\n"
        "    def nested() -> None:\n"
        "        nonlocal client\n"
        "        client.get = object()\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.AMBIGUOUS
    assert handler_call.canonical_symbol is None


def test_function_local_module_alias_abstains_conservatively(tmp_path: Path) -> None:
    """An unanalyzed local alias of the module object cannot preserve exactness."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "def mutate() -> None:\n"
        "    local_api = client\n"
        "    local_api.get = object()\n"
        "def handler(url: str) -> None:\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.AMBIGUOUS
    assert handler_call.canonical_symbol is None


def test_imported_module_passed_to_source_helper_abstains(tmp_path: Path) -> None:
    """An analyzed helper receiving the module can mutate it outside this module."""
    app = tmp_path / "app"
    app.mkdir()
    sites = _call_sites(
        app,
        "import httpx as client\n"
        "def helper(value: object) -> None:\n"
        "    value.get = object()\n"
        "def handler(url: str) -> None:\n"
        "    helper(client)\n"
        "    client.get(url)\n",
    )
    handler_call = next(site for site in sites if site.source_spelling == "client.get")
    assert handler_call.status == CallResolutionStatus.AMBIGUOUS
    assert handler_call.canonical_symbol is None
