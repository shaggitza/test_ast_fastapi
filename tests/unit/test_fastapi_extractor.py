"""Runtime FastAPI extractor parity tests."""

from pathlib import Path

from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor


def test_runtime_extractor_handles_websockets_and_mounted_fastapi(tmp_path: Path) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        """from fastapi import FastAPI

app = FastAPI()
sub = FastAPI()

@app.websocket("/events")
async def events(websocket):
    pass

@sub.get("/status")
def status():
    return {}

app.mount("/sub", sub)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    custom = {
        endpoint.identifier for endpoint in endpoints if endpoint.path in {"/events", "/sub/status"}
    }
    assert custom == {"GET /sub/status", "WEBSOCKET /events"}


def test_runtime_extractor_preserves_slashes_websocket_dependencies_and_mount_cycles(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        """from fastapi import Depends, FastAPI

app = FastAPI()
sub = FastAPI()

def authenticate():
    return "token"

@sub.get("/")
def root():
    return {}

@app.websocket("/events/")
async def events(websocket, token=Depends(authenticate)):
    pass

app.mount("/sub", sub)
app.mount("/cycle", app)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} >= {
        "GET /sub/",
        "WEBSOCKET /events/",
    }
    websocket = next(endpoint for endpoint in endpoints if endpoint.path == "/events/")
    assert websocket.dependencies == ["authenticate"]
