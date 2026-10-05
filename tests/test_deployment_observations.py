from pathlib import Path

from fastapi_endpoint_detector.analyzer.deployment_observations import (
    extract_dockerfile_observations,
    extract_env_observations,
    extract_subprocess_observations,
)


def test_env_observations_keep_route_keys_but_redact_other_values() -> None:
    observations = extract_env_observations(
        "API_BASE_URL=https://api.example.test/v1\n"
        "PORT=8000\n"
        "SECRET_TOKEN=do-not-copy\n"
        "ROOT_PATH=${PREFIX}/api\n"
        "API_URL=https://api.example.test/v1?token=private\n"
    )
    assert [(item.key, item.value, item.certainty) for item in observations] == [
        ("API_BASE_URL", "https://api.example.test/v1", "exact"),
        ("PORT", "8000", "exact"),
        ("SECRET_TOKEN", None, "uncertain"),
        ("ROOT_PATH", None, "uncertain"),
        ("API_URL", None, "uncertain"),
    ]


def test_dockerfile_observations_preserve_static_facts_and_mark_dynamic_forms() -> None:
    observations = extract_dockerfile_observations(
        """FROM python:3.12
ENV API_BASE_URL=https://api.example.test/v1
ENV PORT=8000 ROOT_PATH=/service
ENV ROOT_PATH ${PREFIX}/api
EXPOSE 8000/tcp $PORT
ENTRYPOINT ["uvicorn", "app:api", "--port", "8000"]
CMD uvicorn app:api --port 8000
""",
        Path("Dockerfile"),
    )
    assert [(item.kind, item.key, item.value, item.certainty) for item in observations] == [
        ("environment", "API_BASE_URL", "https://api.example.test/v1", "exact"),
        ("environment", "PORT", "8000", "exact"),
        ("environment", "ROOT_PATH", "/service", "exact"),
        ("environment", "ROOT_PATH", None, "uncertain"),
        ("exposed_port", None, "8000/tcp", "exact"),
        ("exposed_port", None, None, "uncertain"),
        ("container_argv", "entrypoint", ("uvicorn", "app:api", "--port", "8000"), "exact"),
        ("container_argv", "cmd", None, "uncertain"),
    ]


def test_subprocess_observations_require_literal_argv_without_shell() -> None:
    observations = extract_subprocess_observations(
        """import subprocess
subprocess.run(["docker", "run", "image"], check=True)
subprocess.Popen(["uvicorn", "app:api"])
subprocess.run(["sh", "-c", "echo x"], shell=True)
subprocess.run(command, shell=use_shell)
""",
        Path("tool.py"),
    )
    assert [(item.key, item.value, item.certainty) for item in observations] == [
        ("run", ("docker", "run", "image"), "exact"),
        ("Popen", ("uvicorn", "app:api"), "exact"),
        ("run", None, "uncertain"),
        ("run", None, "uncertain"),
    ]
    assert observations[2].uncertainty == "shell execution is excluded"


def test_subprocess_requires_canonical_import_and_rejects_shadowing() -> None:
    canonical_and_aliases = extract_subprocess_observations(
        "import subprocess\n"
        "import subprocess as sp\n"
        "from subprocess import run as run_process\n"
        "subprocess.run(['canonical'])\n"
        "sp.Popen(['module-alias'])\n"
        "run_process(['function-alias'])\n"
    )
    assert [(item.key, item.value, item.certainty) for item in canonical_and_aliases] == [
        ("run", ("canonical",), "exact"),
        ("Popen", ("module-alias",), "exact"),
        ("run", ("function-alias",), "exact"),
    ]

    untrusted = extract_subprocess_observations(
        "subprocess.run(['unimported'])\n"
        "import subprocess\n"
        "subprocess = fake\n"
        "subprocess.run(['rebound'])\n"
        "import subprocess as sp\n"
        "def f(sp):\n"
        "    sp.run(['parameter'])\n"
        ""
    )
    assert untrusted == ()
