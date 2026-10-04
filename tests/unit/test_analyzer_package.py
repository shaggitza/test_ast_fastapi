"""Fresh-process checks for the public analyzer package imports."""

import subprocess
import sys


def test_analyzer_package_defers_mapper_import_and_preserves_public_exports() -> None:
    script = """
import sys
import fastapi_endpoint_detector.analyzer as analyzer
assert 'fastapi_endpoint_detector.analyzer.change_mapper' not in sys.modules
assert 'fastapi_endpoint_detector.analyzer.mypy_analyzer' not in sys.modules
from fastapi_endpoint_detector.analyzer import ChangeMapper, EndpointRegistry, MypyAnalyzer
from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper as DirectMapper
assert ChangeMapper is DirectMapper
assert analyzer.ChangeMapper is ChangeMapper
assert EndpointRegistry.__name__ == 'EndpointRegistry'
assert MypyAnalyzer.__name__ == 'MypyAnalyzer'
try:
    analyzer.missing_export
except AttributeError:
    pass
else:
    raise AssertionError('unknown exports must raise AttributeError')
"""
    subprocess.run([sys.executable, "-c", script], check=True, timeout=30)
