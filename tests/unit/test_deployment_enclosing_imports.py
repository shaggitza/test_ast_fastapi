"""Regressions for resolving enclosing subprocess imports by lexical scope."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.deployment_observations import (
    extract_subprocess_observations,
)


@pytest.mark.parametrize(
    ("source", "argv"),
    [
        pytest.param(
            "def launch():\n    subprocess.run(['module-late'])\nimport subprocess\nlaunch()\n",
            ("module-late",),
            id="module-import-after-function-definition",
        ),
        pytest.param(
            "def outer():\n"
            "    def launch():\n"
            "        subprocess.run(['function-late'])\n"
            "    import subprocess\n"
            "    launch()\n",
            ("function-late",),
            id="function-closure-import-after-inner-definition",
        ),
        pytest.param(
            "def make():\n"
            "    launch = lambda: subprocess.run(['lambda-late'])\n"
            "    import subprocess\n"
            "    return launch\n",
            ("lambda-late",),
            id="lambda-closure-import-after-lambda",
        ),
        pytest.param(
            "def make():\n"
            "    class Runner:\n"
            "        def launch(self):\n"
            "            subprocess.run(['class-closure-late'])\n"
            "    import subprocess\n"
            "    return Runner\n",
            ("class-closure-late",),
            id="class-method-closure-import-after-class",
        ),
        pytest.param(
            "def launch():\n"
            "    global subprocess\n"
            "    subprocess.run(['global-late'])\n"
            "import subprocess\n",
            ("global-late",),
            id="global-function-import-after-definition",
        ),
        pytest.param(
            "def outer():\n"
            "    class Runner:\n"
            "        global subprocess\n"
            "        subprocess.run(['global-class-closure-late'])\n"
            "import subprocess\n",
            ("global-class-closure-late",),
            id="class-global-crosses-deferred-function",
        ),
    ],
)
def test_enclosing_imports_resolve_without_child_line_order(
    source: str, argv: tuple[str, ...]
) -> None:
    # These are static source observations; they do not claim the calls execute.
    observations = extract_subprocess_observations(source, Path("deploy.py"))

    assert [(item.value, item.certainty) for item in observations] == [(argv, "exact")]


@pytest.mark.parametrize(
    "source",
    [
        "subprocess.run(['same-scope-before-import'])\nimport subprocess\n",
        "def launch():\n    subprocess.run(['same-scope-before-import'])\n    import subprocess\n",
    ],
)
def test_same_scope_import_after_call_is_not_resolved(source: str) -> None:
    assert extract_subprocess_observations(source, Path("deploy.py")) == ()


@pytest.mark.parametrize(
    "source",
    [
        "class Runner:\n    subprocess.run(['class-before-module-import'])\nimport subprocess\n",
        "class Runner:\n"
        "    global subprocess\n"
        "    subprocess.run(['class-global-before-module-import'])\n"
        "import subprocess\n",
        "def outer():\n"
        "    [subprocess.run(['comprehension-before-function-import']) for _ in (0,)]\n"
        "    import subprocess\n",
        "class Runner:\n    subprocess.run(['class-before-class-import'])\n    import subprocess\n",
        "class Outer:\n"
        "    class Runner:\n"
        "        subprocess.run(['nested-class-before-module-import'])\n"
        "import subprocess\n",
        "[subprocess.run(['comprehension-before-module-import']) for _ in (0,)]\n"
        "import subprocess\n",
        "def outer():\n"
        "    class Runner:\n"
        "        subprocess.run(['class-before-function-import'])\n"
        "    import subprocess\n",
    ],
)
def test_immediate_class_and_comprehension_bodies_keep_ancestor_order(source: str) -> None:
    assert extract_subprocess_observations(source, Path("deploy.py")) == ()


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\ndef launch(subprocess):\n    subprocess.run(['parameter-shadow'])\n",
        "def outer():\n"
        "    import subprocess\n"
        "    def launch():\n"
        "        subprocess.run(['enclosing-rebind'])\n"
        "    subprocess = object()\n"
        "    return launch\n",
        "def outer():\n"
        "    if enabled:\n"
        "        import subprocess\n"
        "    def launch():\n"
        "        subprocess.run(['conditional-import'])\n"
        "    return launch\n",
    ],
)
def test_shadowed_or_conditional_enclosing_bindings_remain_unresolved(
    source: str,
) -> None:
    assert extract_subprocess_observations(source, Path("deploy.py")) == ()
