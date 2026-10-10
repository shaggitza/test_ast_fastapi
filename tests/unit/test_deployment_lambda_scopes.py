"""Python lexical-scope regressions for subprocess source observations."""

from __future__ import annotations

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.deployment_observations import (
    extract_subprocess_observations,
)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param(
            "subprocess.run(['outer'])\ncallback = lambda subprocess: None\n",
            (("outer",),),
            id="lambda_parameter",
        ),
        pytest.param(
            "subprocess.run(['outer'])\ncallback = lambda *, subprocess=None: None\n",
            (("outer",),),
            id="lambda_kwonly",
        ),
        pytest.param(
            "subprocess.run(['outer'])\ncallback = lambda: (subprocess := object())\n",
            (("outer",),),
            id="lambda_local_walrus",
        ),
        pytest.param(
            "subprocess.run(['outer'])\n"
            "callback = lambda: (subprocess.run(['invalid']), (subprocess := object()))\n",
            (("outer",),),
            id="lambda_before_local_walrus",
        ),
        pytest.param(
            "def launch():\n"
            "    subprocess.run(['outer'])\n"
            "    callback = lambda subprocess: None\n",
            (("outer",),),
            id="function_lambda_parameter",
        ),
        pytest.param(
            "subprocess.run(['outer'])\ncallback = lambda dep=(subprocess := object()): None\n",
            (),
            id="lambda_default_outer_write",
        ),
        pytest.param(
            "callback = lambda subprocess: subprocess.run(['foreign'])\n",
            (),
            id="lambda_parameter_body",
        ),
        pytest.param(
            "class C:\n    import subprocess as sp\n    callback = lambda: sp.run(['invalid'])\n",
            (),
            id="class_scope_not_captured",
        ),
        pytest.param(
            "class C:\n"
            "    subprocess = object()\n"
            "    callback = lambda: subprocess.run(['global'])\n",
            (("global",),),
            id="class_shadow_skipped",
        ),
        pytest.param(
            "class C:\n"
            "    import subprocess as sp\n"
            "    callback = lambda dep=sp.run(['default']): sp.run(['invalid'])\n",
            (("default",),),
            id="class_default_uses_class",
        ),
        pytest.param(
            "callback = lambda: subprocess.run(['captured'])\n",
            (("captured",),),
            id="lambda_module_capture",
        ),
        pytest.param(
            "class A:\n"
            "    import subprocess as sp\n"
            "    class B:\n"
            "        callback = lambda: sp.run(['invalid'])\n",
            (),
            id="nested_class_not_captured",
        ),
        pytest.param(
            "class A:\n"
            "    import subprocess as sp\n"
            "    class B:\n"
            "        def callback(self):\n"
            "            return sp.run(['invalid'])\n",
            (),
            id="nested_class_method_not_captured",
        ),
        pytest.param(
            "class A:\n"
            "    import subprocess as sp\n"
            "    calls = [sp.run(['invalid']) for _ in [sp.run(['first_iter'])]]\n",
            (("first_iter",),),
            id="class_comprehension_first_iter_only",
        ),
        pytest.param(
            "def make():\n"
            "    import subprocess as sp\n"
            "    class A:\n"
            "        class B:\n"
            "            callback = lambda: sp.run(['captured'])\n",
            (("captured",),),
            id="nested_class_function_closure",
        ),
    ],
)
def test_subprocess_observations_respect_lambda_and_class_scope(
    body: str, expected: tuple[tuple[str, ...], ...]
) -> None:
    observations = extract_subprocess_observations("import subprocess\n" + body, Path("deploy.py"))

    assert tuple(row.value for row in observations) == expected
    assert all(row.certainty == "exact" for row in observations)
    assert all(row.source_path == Path("deploy.py") for row in observations)
